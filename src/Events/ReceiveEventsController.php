<?php

namespace EasySuite\Common\Events;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Support\Problem;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/** POST /s2s/events: Empfang von SETs (RFC 8935 Push). Geschützt durch easysuite.token + easysuite.type:app. */
class ReceiveEventsController extends Controller
{
    public function __invoke(Request $request, SetVerifier $verifier, EventRegistry $registry, Cache $cache): Response
    {
        $jwt = trim($request->getContent());

        if ($jwt === '') {
            return Problem::response(400, 'Empty body.');
        }

        try {
            $events = $verifier->verify($jwt);
        } catch (InvalidTokenException $e) {
            return Problem::response(400, 'Invalid security event token.');
        }

        $jti = $events[0]->jti ?? null;
        $key = 'easysuite:event-jti:'.$jti;

        // Idempotenz: dieselbe jti wird nur einmal verarbeitet, weitere Zustellungen bestätigen wir still.
        if ($jti !== null && ! $cache->add($key, 1, (int) config('easysuite.events.dedupe_ttl'))) {
            return response('', 202);
        }

        try {
            foreach ($events as $event) {
                $registry->dispatch($event);
            }
        } catch (Throwable $e) {
            $cache->forget($key);

            throw $e;
        }

        return response('', 202);
    }
}
