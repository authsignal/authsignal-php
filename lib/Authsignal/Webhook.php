<?php

namespace Authsignal;

class Webhook
{
    private string $apiSecretKey;
    private const DEFAULT_TOLERANCE = 5; // minutes
    private const VERSION = "v2";

    public function __construct(string $apiSecretKey)
    {
        $this->apiSecretKey = $apiSecretKey;
    }

    /**
     * @throws InvalidSignatureException
     */
    public function constructEvent(string $payload, string $signatureHeader, int $tolerance = self::DEFAULT_TOLERANCE): object
    {
        $parsedSignature = $this->parseSignature($signatureHeader);

        $secondsSinceEpoch = time();

        if ($tolerance > 0 && $parsedSignature->timestamp < $secondsSinceEpoch - ($tolerance * 60)) {
            throw new InvalidSignatureException("Timestamp is outside the tolerance zone.");
        }

        $hmacContent = $parsedSignature->timestamp . "." . $payload;

        $computedSignature = str_replace("=", "", base64_encode(hash_hmac("sha256", $hmacContent, $this->apiSecretKey, true)));

        $match = false;

        foreach ($parsedSignature->signatures as $signature) {
            if (hash_equals($signature, $computedSignature)) {
                $match = true;
                break;
            }
        }

        if (!$match) {
            throw new InvalidSignatureException("Signature mismatch.");
        }

        return json_decode($payload);
    }

    /**
     * @throws InvalidSignatureException
     */
    private function parseSignature(string $value): object
    {
        $timestamp = -1;
        $signatures = [];

        $items = explode(",", $value);

        foreach ($items as $item) {
            $kv = explode("=", $item, 2);
            if (count($kv) === 2) {
                if ($kv[0] === "t") {
                    $timestamp = intval($kv[1]);
                } elseif ($kv[0] === self::VERSION) {
                    $signatures[] = $kv[1];
                }
            }
        }

        if ($timestamp === -1 || empty($signatures)) {
            throw new InvalidSignatureException("Signature format is invalid.");
        }

        return (object) [
            "timestamp" => $timestamp,
            "signatures" => $signatures,
        ];
    }
} 