<?php
namespace App\Config;

use Twilio\Rest\Client;

class Sms {
    public static function send($to, $message) {
        $sid = $_ENV['TWILIO_SID'] ?? '';
        $token = $_ENV['TWILIO_AUTH_TOKEN'] ?? '';
        $from = $_ENV['TWILIO_FROM'] ?? '';
        if (!$sid || !$token || !$from) return false;
        try {
            $client = new Client($sid, $token);
            $client->messages->create($to, [
                'from' => $from,
                'body' => $message
            ]);
            return true;
        } catch (\Exception $e) {
            // Optionally log $e->getMessage()
            return false;
        }
    }
}
