/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { timeout } from '../../../../base/common/async.js';
import { CancellationToken } from '../../../../base/common/cancellation.js';
import { Emitter } from '../../../../base/common/event.js';
import { getErrorMessage } from '../../../../base/common/errors.js';
import { Disposable } from '../../../../base/common/lifecycle.js';
import { IHeaders } from '../../../../base/parts/request/common/request.js';
import { localize } from '../../../../nls.js';
import { InstantiationType, registerSingleton } from '../../../../platform/instantiation/common/extensions.js';
import { ILogService } from '../../../../platform/log/common/log.js';
import { IRequestService, NO_FETCH_TELEMETRY, asText, isSuccess } from '../../../../platform/request/common/request.js';
import { ISecretStorageService } from '../../../../platform/secrets/common/secrets.js';
import { IEthernalAuthenticationService, IEthernalDeviceCode, IEthernalMinecraftProfile } from '../common/ethernalAuthentication.js';

const MSA_CLIENT_ID = '607fb49a-9e85-4e48-ac10-2cc659183068';
const MSA_TENANT = 'consumers';
const MSA_SCOPE = 'openid offline_access XboxLive.signin';
const SESSION_SECRET_KEY = 'ethernal.minecraft.auth';
const SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const DEVICE_CODE_MAX_WAIT_SECONDS = 10 * 60;

const FORM_HEADERS: IHeaders = {
	'Content-Type': 'application/x-www-form-urlencoded',
	'Accept': 'application/json'
};

const JSON_HEADERS: IHeaders = {
	'Content-Type': 'text/plain',
	'Accept': 'application/json'
};

interface IRequestTextResult {
	readonly success: boolean;
	readonly statusCode: number | undefined;
	readonly text: string;
}

interface IDeviceCodeResponse {
	readonly user_code?: string;
	readonly device_code?: string;
	readonly verification_uri?: string;
	readonly message?: string;
	readonly interval?: number;
}

interface ITokenResponse {
	readonly access_token?: string;
	readonly refresh_token?: string;
	readonly expires_in?: number;
	readonly error?: string;
	readonly error_description?: string;
}

interface IXuiEntry {
	readonly uhs?: string;
}

interface IXuiClaims {
	readonly xui?: IXuiEntry[];
}

interface IXblAuthResponse {
	readonly Token?: string;
	readonly DisplayClaims?: IXuiClaims;
}

interface IXstsAuthResponse {
	readonly Token?: string;
	readonly DisplayClaims?: IXuiClaims;
}

interface IMinecraftAuthResponse {
	readonly access_token?: string;
	readonly expires_in?: number;
}

interface IMinecraftEntitlementItem {
	readonly name?: string;
}

interface IMinecraftEntitlements {
	readonly items?: IMinecraftEntitlementItem[];
}

interface IMinecraftProfileResponse {
	readonly id?: string;
	readonly name?: string;
}

interface IEthernalMinecraftSession {
	readonly profile: IEthernalMinecraftProfile;
	readonly minecraftAccessToken: string;
	readonly refreshToken?: string;
	readonly expiresAt: number;
}

export class EthernalAuthenticationService extends Disposable implements IEthernalAuthenticationService {
	declare readonly _serviceBrand: undefined;

	private readonly _onDidChangeProfile = this._register(new Emitter<IEthernalMinecraftProfile | undefined>());
	readonly onDidChangeProfile = this._onDidChangeProfile.event;

	private currentProfile: IEthernalMinecraftProfile | undefined;
	private currentProfilePromise: Promise<IEthernalMinecraftProfile | undefined> | undefined;

	constructor(
		@IRequestService private readonly requestService: IRequestService,
		@ISecretStorageService private readonly secretStorageService: ISecretStorageService,
		@ILogService private readonly logService: ILogService
	) {
		super();
	}

	async getCurrentProfile(): Promise<IEthernalMinecraftProfile | undefined> {
		if (this.currentProfile) {
			return this.currentProfile;
		}

		this.currentProfilePromise ??= this.resolveCurrentProfile();
		try {
			return await this.currentProfilePromise;
		} finally {
			this.currentProfilePromise = undefined;
		}
	}

	async beginDeviceCode(): Promise<IEthernalDeviceCode> {
		const response = await this.requestJson<IDeviceCodeResponse>({
			url: this.deviceCodeEndpoint,
			type: 'POST',
			headers: FORM_HEADERS,
			data: this.form({
				client_id: MSA_CLIENT_ID,
				scope: MSA_SCOPE
			}),
			label: localize('ethernal.auth.microsoftDeviceCode', "Microsoft device sign-in")
		});

		const userCode = this.requireString(response.user_code, localize('ethernal.auth.noUserCode', "Microsoft did not return a sign-in code."));
		const verificationUri = this.requireString(response.verification_uri, localize('ethernal.auth.noVerificationUri', "Microsoft did not return a verification URL."));
		const deviceCode = this.requireString(response.device_code, localize('ethernal.auth.noDeviceCode', "Microsoft did not return a device code."));

		return {
			userCode,
			verificationUri,
			deviceCode,
			intervalSeconds: typeof response.interval === 'number' && response.interval > 0 ? response.interval : 5,
			message: response.message || localize('ethernal.auth.openBrowser', "Open the Microsoft page and enter the code.")
		};
	}

	async completeDeviceCode(deviceCode: string, intervalSeconds: number): Promise<IEthernalMinecraftProfile> {
		const token = await this.pollForMsaToken(deviceCode, intervalSeconds);
		return this.completeLoginFlow(token.accessToken, token.refreshToken);
	}

	async signOut(): Promise<void> {
		await this.secretStorageService.delete(SESSION_SECRET_KEY);
		this.setCurrentProfile(undefined);
	}

	private async resolveCurrentProfile(): Promise<IEthernalMinecraftProfile | undefined> {
		const session = await this.readSession();
		if (!session) {
			return undefined;
		}

		if (session.expiresAt > Date.now() + 60_000) {
			this.setCurrentProfile(session.profile);
			return session.profile;
		}

		if (!session.refreshToken) {
			await this.signOut();
			return undefined;
		}

		try {
			const refreshed = await this.refreshMsaToken(session.refreshToken);
			return this.completeLoginFlow(refreshed.accessToken, refreshed.refreshToken ?? session.refreshToken);
		} catch (error) {
			this.logService.warn('[EthernalAuthenticationService] Failed to refresh stored Minecraft session:', getErrorMessage(error));
			await this.signOut();
			return undefined;
		}
	}

	private async pollForMsaToken(deviceCode: string, intervalSeconds: number): Promise<{ accessToken: string; refreshToken?: string }> {
		let interval = Math.max(5, intervalSeconds || 5);
		let waited = 0;

		while (waited < DEVICE_CODE_MAX_WAIT_SECONDS) {
			const response = await this.requestText({
				url: this.tokenEndpoint,
				type: 'POST',
				headers: FORM_HEADERS,
				data: this.form({
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					client_id: MSA_CLIENT_ID,
					device_code: deviceCode
				})
			});

			const token = this.tryParseJson<ITokenResponse>(response.text);
			if (response.success) {
				const accessToken = token?.access_token;
				if (accessToken) {
					return {
						accessToken,
						refreshToken: token.refresh_token
					};
				}

				throw new Error(localize('ethernal.auth.noMsaAccessToken', "Microsoft did not return an access token."));
			}

			switch (token?.error) {
				case 'authorization_pending':
					await timeout(interval * 1000);
					waited += interval;
					break;
				case 'slow_down':
					interval += 5;
					await timeout(interval * 1000);
					waited += interval;
					break;
				case 'expired_token':
				case 'invalid_grant':
					throw new Error(localize('ethernal.auth.codeExpired', "The Microsoft sign-in code expired. Please try again."));
				default:
					throw new Error(localize('ethernal.auth.msaFailed', "Microsoft sign-in failed: {0}", token?.error_description || this.extractRemoteError(response.text)));
			}
		}

		throw new Error(localize('ethernal.auth.timeout', "The Microsoft sign-in timed out. Please try again."));
	}

	private async refreshMsaToken(refreshToken: string): Promise<{ accessToken: string; refreshToken?: string }> {
		const response = await this.requestJson<ITokenResponse>({
			url: this.tokenEndpoint,
			type: 'POST',
			headers: FORM_HEADERS,
			data: this.form({
				grant_type: 'refresh_token',
				client_id: MSA_CLIENT_ID,
				refresh_token: refreshToken,
				scope: MSA_SCOPE
			}),
			label: localize('ethernal.auth.microsoftRefresh', "Microsoft token refresh")
		});

		return {
			accessToken: this.requireString(response.access_token, localize('ethernal.auth.noRefreshTokenAccess', "Microsoft did not return a refreshed access token.")),
			refreshToken: response.refresh_token
		};
	}

	private async completeLoginFlow(msaAccessToken: string, refreshToken: string | undefined): Promise<IEthernalMinecraftProfile> {
		const xbl = await this.requestJson<IXblAuthResponse>({
			url: 'https://user.auth.xboxlive.com/user/authenticate',
			type: 'POST',
			headers: JSON_HEADERS,
			data: JSON.stringify({
				Properties: {
					AuthMethod: 'RPS',
					SiteName: 'user.auth.xboxlive.com',
					RpsTicket: `d=${msaAccessToken}`
				},
				RelyingParty: 'http://auth.xboxlive.com',
				TokenType: 'JWT'
			}),
			label: localize('ethernal.auth.xboxLive', "Xbox Live authentication")
		});

		const xblToken = this.requireString(xbl.Token, localize('ethernal.auth.noXboxToken', "Xbox Live did not return a user token."));
		const userHash = this.requireString(xbl.DisplayClaims?.xui?.[0]?.uhs, localize('ethernal.auth.noXboxUserHash', "Xbox Live did not return the user hash."));

		const xsts = await this.requestJson<IXstsAuthResponse>({
			url: 'https://xsts.auth.xboxlive.com/xsts/authorize',
			type: 'POST',
			headers: JSON_HEADERS,
			data: JSON.stringify({
				Properties: {
					SandboxId: 'RETAIL',
					UserTokens: [xblToken]
				},
				RelyingParty: 'rp://api.minecraftservices.com/',
				TokenType: 'JWT'
			}),
			label: localize('ethernal.auth.xsts', "Xbox security token authorization")
		});

		const xstsToken = this.requireString(xsts.Token, localize('ethernal.auth.noXstsToken', "Xbox did not return a security token."));
		const identityToken = `XBL3.0 x=${userHash};${xstsToken}`;

		const minecraftAuth = await this.requestJson<IMinecraftAuthResponse>({
			url: 'https://api.minecraftservices.com/authentication/login_with_xbox',
			type: 'POST',
			headers: JSON_HEADERS,
			data: JSON.stringify({ identityToken }),
			label: localize('ethernal.auth.minecraftLogin', "Minecraft authentication")
		});

		const minecraftAccessToken = this.requireString(minecraftAuth.access_token, localize('ethernal.auth.noMinecraftToken', "Minecraft did not return an access token."));
		await this.validateEntitlements(minecraftAccessToken);
		const profile = await this.fetchMinecraftProfile(minecraftAccessToken);

		await this.writeSession({
			profile,
			minecraftAccessToken,
			refreshToken,
			expiresAt: Date.now() + ((minecraftAuth.expires_in && minecraftAuth.expires_in > 0 ? minecraftAuth.expires_in * 1000 : SESSION_MAX_AGE_MS))
		});

		this.setCurrentProfile(profile);
		return profile;
	}

	private async validateEntitlements(minecraftAccessToken: string): Promise<void> {
		const entitlements = await this.requestJson<IMinecraftEntitlements>({
			url: 'https://api.minecraftservices.com/entitlements/mcstore',
			headers: {
				'Accept': 'application/json',
				'Authorization': `Bearer ${minecraftAccessToken}`
			},
			label: localize('ethernal.auth.minecraftEntitlements', "Minecraft license validation")
		});

		const hasGame = entitlements.items?.some(item => item.name === 'game_minecraft') ?? false;
		if (!hasGame) {
			throw new Error(localize('ethernal.auth.noMinecraftLicense', "This Microsoft account does not own Minecraft Java or Bedrock."));
		}
	}

	private async fetchMinecraftProfile(minecraftAccessToken: string): Promise<IEthernalMinecraftProfile> {
		const profile = await this.requestJson<IMinecraftProfileResponse>({
			url: 'https://api.minecraftservices.com/minecraft/profile',
			headers: {
				'Accept': 'application/json',
				'Authorization': `Bearer ${minecraftAccessToken}`
			},
			label: localize('ethernal.auth.minecraftProfile', "Minecraft profile")
		});

		const gamertag = this.requireString(profile.name, localize('ethernal.auth.noMinecraftName', "Minecraft did not return a profile name."));
		const uuid = this.requireString(profile.id, localize('ethernal.auth.noMinecraftUuid', "Minecraft did not return a profile ID."));

		if (!gamertag || gamertag === 'authenticated_user' || gamertag.startsWith('Player')) {
			throw new Error(localize('ethernal.auth.invalidMinecraftProfile', "Minecraft returned an invalid profile name: {0}", gamertag));
		}

		return { gamertag, uuid };
	}

	private async requestJson<T>(options: { url: string; type?: string; headers?: IHeaders; data?: string; label: string }): Promise<T> {
		const response = await this.requestText(options);
		if (!response.success) {
			throw new Error(localize('ethernal.auth.requestFailed', "{0} failed ({1}): {2}", options.label, response.statusCode?.toString() ?? localize('ethernal.auth.unknownStatus', "unknown status"), this.extractRemoteError(response.text)));
		}

		if (!response.text) {
			throw new Error(localize('ethernal.auth.emptyResponse', "{0} returned an empty response.", options.label));
		}

		return this.parseJson<T>(response.text, options.label);
	}

	private async requestText(options: { url: string; type?: string; headers?: IHeaders; data?: string }): Promise<IRequestTextResult> {
		const context = await this.requestService.request({
			url: options.url,
			type: options.type ?? 'GET',
			headers: options.headers,
			data: options.data,
			callSite: NO_FETCH_TELEMETRY
		}, CancellationToken.None);

		return {
			success: isSuccess(context),
			statusCode: context.res.statusCode,
			text: await asText(context) ?? ''
		};
	}

	private parseJson<T>(text: string, label: string): T {
		try {
			return JSON.parse(text) as T;
		} catch {
			throw new Error(localize('ethernal.auth.invalidJson', "{0} returned invalid JSON.", label));
		}
	}

	private tryParseJson<T>(text: string): T | undefined {
		try {
			return JSON.parse(text) as T;
		} catch {
			return undefined;
		}
	}

	private extractRemoteError(text: string): string {
		if (!text) {
			return localize('ethernal.auth.noResponseBody', "No response body.");
		}

		const parsed = this.tryParseJson<{ error_description?: string; error?: string; message?: string; XErr?: number }>(text);
		return parsed?.error_description ?? parsed?.message ?? parsed?.error ?? (typeof parsed?.XErr === 'number' ? parsed.XErr.toString() : this.trimErrorText(text));
	}

	private trimErrorText(text: string): string {
		return text.length > 500 ? `${text.slice(0, 500)}...` : text;
	}

	private form(values: Record<string, string>): string {
		const form = new URLSearchParams();
		for (const [key, value] of Object.entries(values)) {
			form.set(key, value);
		}
		return form.toString();
	}

	private requireString(value: string | undefined, message: string): string {
		if (!value) {
			throw new Error(message);
		}
		return value;
	}

	private async readSession(): Promise<IEthernalMinecraftSession | undefined> {
		try {
			const rawSession = await this.secretStorageService.get(SESSION_SECRET_KEY);
			if (!rawSession) {
				return undefined;
			}

			const parsed: unknown = JSON.parse(rawSession);
			if (this.isSession(parsed)) {
				return parsed;
			}
		} catch (error) {
			this.logService.warn('[EthernalAuthenticationService] Failed to read Minecraft session:', getErrorMessage(error));
		}

		await this.secretStorageService.delete(SESSION_SECRET_KEY);
		return undefined;
	}

	private async writeSession(session: IEthernalMinecraftSession): Promise<void> {
		await this.secretStorageService.set(SESSION_SECRET_KEY, JSON.stringify(session));
	}

	private isSession(value: unknown): value is IEthernalMinecraftSession {
		if (!this.isRecord(value) || !this.isProfile(value.profile)) {
			return false;
		}

		return typeof value.minecraftAccessToken === 'string'
			&& (typeof value.refreshToken === 'undefined' || typeof value.refreshToken === 'string')
			&& typeof value.expiresAt === 'number';
	}

	private isProfile(value: unknown): value is IEthernalMinecraftProfile {
		return this.isRecord(value)
			&& typeof value.gamertag === 'string'
			&& typeof value.uuid === 'string';
	}

	private isRecord(value: unknown): value is Record<string, unknown> {
		return typeof value === 'object' && value !== null;
	}

	private setCurrentProfile(profile: IEthernalMinecraftProfile | undefined): void {
		if (this.currentProfile?.uuid === profile?.uuid && this.currentProfile?.gamertag === profile?.gamertag) {
			return;
		}

		this.currentProfile = profile;
		this._onDidChangeProfile.fire(profile);
	}

	private get deviceCodeEndpoint(): string {
		return `https://login.microsoftonline.com/${MSA_TENANT}/oauth2/v2.0/devicecode`;
	}

	private get tokenEndpoint(): string {
		return `https://login.microsoftonline.com/${MSA_TENANT}/oauth2/v2.0/token`;
	}
}

registerSingleton(IEthernalAuthenticationService, EthernalAuthenticationService, InstantiationType.Delayed);
