<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('easysuite_event_outbox', function (Blueprint $table) {
            $table->uuid('id')->primary();                    // wird als `jti` des SET verwendet
            $table->string('event_type', 255);                // URI
            $table->string('tid', 36)->nullable()->index();
            $table->string('txn', 64)->nullable();
            $table->json('payload');
            $table->string('audience');                       // `aud` des SET (Empfänger-URL)
            $table->string('s2s_audience')->nullable();       // client_id des Empfängers für das S2S-Token
            $table->string('endpoint');
            $table->string('status', 16)->default('pending'); // pending | delivered | dead
            $table->unsignedSmallInteger('attempts')->default(0);
            $table->timestamp('next_attempt_at')->nullable();
            $table->text('last_error')->nullable();
            $table->timestamp('delivered_at')->nullable();
            $table->timestamps();

            $table->index(['status', 'next_attempt_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('easysuite_event_outbox');
    }
};
