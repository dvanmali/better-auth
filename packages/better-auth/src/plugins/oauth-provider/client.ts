import type { oauthProvider } from "./oauth";
import type { BetterAuthClientPlugin } from "../../types";
import { verifyAccessToken } from "./verify";
import type { JWTVerifyOptions } from "jose";
import { handleMcpErrors } from "./mcp";

interface VerifyAccessTokenRemote {
	/** Full url of the introspect endpoint. Should end with `/oauth2/introspect` */
	introspectUrl: string;
	/** Client Secret */
	clientId: string;
	/** Client Secret */
	clientSecret: string;
	/**
	 * Forces remote verification of a token.
	 * This ensures attached session (if applicable)
	 * is also still active.
	 */
	force?: boolean;
}

export const oauthProviderClient = () => {
	return {
		id: "oauth-provider-client",
		$InferServerPlugin: {} as ReturnType<typeof oauthProvider>,
		getActions() {
			return {
				verifyAccessToken: async (
					token: string,
					opts: {
						/** Verify options */
						verifyOptions: JWTVerifyOptions &
							Required<Pick<JWTVerifyOptions, "audience" | "issuer">>;
						/** Scopes to additionally verify. Token must include all but not exact. */
						scopes?: string[];
						/** Required to verify access token locally */
						jwksUrl?: string;
						/** If provided, can verify a token remotely */
						remoteVerify?: VerifyAccessTokenRemote;
					},
				) => {
					try {
						return await verifyAccessToken(token, opts);
					} catch (error) {
						handleMcpErrors(error, opts.verifyOptions.audience);
					}
				},
			};
		},
	} satisfies BetterAuthClientPlugin;
};
