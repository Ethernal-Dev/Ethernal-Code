/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Event } from '../../../../base/common/event.js';
import { createDecorator } from '../../../../platform/instantiation/common/instantiation.js';

export const IEthernalAuthenticationService = createDecorator<IEthernalAuthenticationService>('ethernalAuthenticationService');

export interface IEthernalMinecraftProfile {
	readonly gamertag: string;
	readonly uuid: string;
}

export interface IEthernalDeviceCode {
	readonly userCode: string;
	readonly verificationUri: string;
	readonly message: string;
	readonly intervalSeconds: number;
	readonly deviceCode: string;
}

export interface IEthernalAuthenticationService {
	readonly _serviceBrand: undefined;

	readonly onDidChangeProfile: Event<IEthernalMinecraftProfile | undefined>;

	getCurrentProfile(): Promise<IEthernalMinecraftProfile | undefined>;
	beginDeviceCode(): Promise<IEthernalDeviceCode>;
	completeDeviceCode(deviceCode: string, intervalSeconds: number): Promise<IEthernalMinecraftProfile>;
	signOut(): Promise<void>;
}
