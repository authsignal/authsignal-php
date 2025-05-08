<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';
require_once dirname(__DIR__) . '/lib/Authsignal.php';

use Authsignal\InvalidSignatureException;
use PHPUnit\Framework\TestCase;

class WebhookTest extends TestCase
{
    private const TEST_API_SECRET_KEY = 'test-secret-key-123';

    public function setUp(): void
    {
        \Authsignal::setApiSecretKey(self::TEST_API_SECRET_KEY);
    }

    public function testInvalidSignatureFormat()
    {
        $payload = '{}';
        $signature = '123';

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('Signature format is invalid.');

        \Authsignal::webhook()->constructEvent($payload, $signature);
    }

    public function testTimestampToleranceError()
    {
        $payload = '{}';

        $signature = 't=1630000000,v2=invalid_signature';

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('Timestamp is outside the tolerance zone.');

        \Authsignal::webhook()->constructEvent($payload, $signature);
    }

    public function testInvalidComputedSignature()
    {
        $payload = '{}';
        $timestamp = time(); 
        $signature = "t={$timestamp},v2=invalid_signature";

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('Signature mismatch.');

        \Authsignal::webhook()->constructEvent($payload, $signature);
    }

    public function testValidSignature()
    {
        $payload = json_encode([
            'version' => 1,
            'id' => 'bc1598bc-e5d6-4c69-9afb-1a6fe3469d6e',
            'source' => 'https://authsignal.com',
            'time' => '2025-02-20T01:51:56.070Z',
            'tenantId' => '7752d28e-e627-4b1b-bb81-b45d68d617bc',
            'type' => 'email.created',
            'data' => [
                'to' => 'test@example.com',
                'code' => '157743',
                'userId' => 'b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0',
                'actionCode' => 'accountRecovery',
                'idempotencyKey' => 'ba8c1a7c-775d-4dff-9abe-be798b7b8bb9',
                'verificationMethod' => 'EMAIL_OTP',
            ],
        ]);

        $timestamp = 1740016316;
        $hmacContent = $timestamp . "." . $payload;
        $computedSignature = str_replace("=", "", base64_encode(hash_hmac("sha256", $hmacContent, self::TEST_API_SECRET_KEY, true)));
        $signature = "t={$timestamp},v2={$computedSignature}";

        $tolerance = -1;

        $event = \Authsignal::webhook()->constructEvent($payload, $signature, $tolerance);

        $this->assertIsObject($event);
        $this->assertEquals(1, $event->version);
        $this->assertEquals('accountRecovery', $event->data->actionCode);
    }

    public function testValidSignatureWhenTwoApiKeysActive()
    {
        $payload = json_encode([
            'version' => 1,
            'id' => 'af7be03c-ea8f-4739-b18e-8b48fcbe4e38',
            'source' => 'https://authsignal.com',
            'time' => '2025-02-20T01:47:17.248Z',
            'tenantId' => '7752d28e-e627-4b1b-bb81-b45d68d617bc',
            'type' => 'email.created',
            'data' => [
                'to' => 'test@example.com',
                'code' => '718190',
                'userId' => 'b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0',
                'actionCode' => 'accountRecovery',
                'idempotencyKey' => '68d68190-fac9-4e91-b277-c63d31d3c6b1',
                'verificationMethod' => 'EMAIL_OTP',
            ],
        ]);

        $timestamp = 1740016037;
        $hmacContent = $timestamp . "." . $payload;
        $validSignature = str_replace("=", "", base64_encode(hash_hmac("sha256", $hmacContent, self::TEST_API_SECRET_KEY, true)));
        
        $signature = "t={$timestamp},v2=zI5rg1XJtKH8dXTX9VCSwy07qTPJliXkK9ppgNjmzqw,v2={$validSignature}";

        $tolerance = -1;

        $event = \Authsignal::webhook()->constructEvent($payload, $signature, $tolerance);

        $this->assertIsObject($event);
        $this->assertEquals(1, $event->version);
    }
} 