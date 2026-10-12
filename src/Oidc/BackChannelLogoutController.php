<?php

namespace EasySuite\Common\Oidc;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\TokenVerifier;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;

/** OIDC Back-Channel Logout 1.0: POST logout_token (Form). */
class BackChannelLogoutController extends Controller
{
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __invoke(
        Request $request,
        OidcClient $oidc,
        TokenVerifier $verifier,
        RevokedSessions $revoked,
        Cache $cache,
    ): Response {
        $headers = ['Cache-Control' => 'no-store'];
        $jwt = $request->input('logout_token');

        if (! is_string($jwt) || $jwt === '') {
            return response(['error' => 'invalid_request'], 400, $headers);
        }

        try {
            $token = $verifier->verify(
                $jwt,
                $oidc->issuer(),
                $oidc->jwksUri(),
                config('easysuite.client_id'),
                config('easysuite.leeway'),
                requireExp: false,
            );
        } catch (InvalidTokenException) {
            return response(['error' => 'invalid_request'], 400, $headers);
        }

        $events = (array) $token->claim('events', []);

        if (! array_key_exists(self::EVENT, $events)
            || $token->claim('nonce') !== null
            || ($token->sid() === null && $token->sub() === null)
            || $token->jti() === null) {
            return response(['error' => 'invalid_request'], 400, $headers);
        }

        // Replay-Schutz
        if (! $cache->add('easysuite:logout-jti:'.$token->jti(), 1, 3600)) {
            return response('', 200, $headers);
        }

        if ($token->sid() !== null) {
            $revoked->revokeSession($token->sid());
        } else {
            $revoked->revokeSubject($token->sub());
        }

        return response('', 200, $headers);
    }
}
