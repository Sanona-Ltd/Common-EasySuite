<?php

namespace EasySuite\Common\Http\Middleware;

use Closure;
use EasySuite\Common\Jwt\VerifiedToken;
use EasySuite\Common\Support\Problem;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `easysuite.type:user` oder `easysuite.type:app`.
 * Trennt Delegation (Mensch) von S2S (client_credentials): ein App-Token darf keine User-Routen bedienen und umgekehrt.
 */
class RequireTokenType
{
    public function handle(Request $request, Closure $next, string $type): Response
    {
        /** @var VerifiedToken|null $token */
        $token = $request->attributes->get(RequireToken::ATTRIBUTE);

        if (! $token) {
            return Problem::unauthorized('Missing bearer token.', null, 'invalid_request');
        }

        if ($token->type() !== $type) {
            return Problem::response(403, 'Wrong token type.', "This endpoint requires a {$type} token.");
        }

        return $next($request);
    }
}
