<?php

namespace EasySuite\Common\Events;

use EasySuite\Common\Jwt\Jwk;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;

/** GET /.well-known/jwks.json: öffentlicher Schlüssel dieses Systems zur Prüfung seiner Events. */
class JwksController extends Controller
{
    public function __invoke(SetSigner $signer): JsonResponse
    {
        abort_unless($signer->isConfigured(), 404);

        return response()
            ->json(['keys' => [Jwk::fromPublicPem($signer->publicPem())]])
            ->header('Cache-Control', 'public, max-age=300');
    }
}
