<?php
namespace App\Config;

use Postmark\PostmarkClient;

class Mailer {
    public static function send($to, $subject, $htmlBody, $textBody = '') {
        $apiKey = $_ENV['POSTMARK_API_KEY'] ?? '';
        $from = $_ENV['MAIL_FROM'] ?? '';
        $messageStream = $_ENV['POSTMARK_MESSAGE_STREAM'] ?? 'outbound'; // Default to 'outbound'
        if (!$apiKey || !$from) return false;
        $client = new PostmarkClient($apiKey);
        try {
            $sendResult = $client->sendEmail(
                $from,
                $to,
                $subject,
                $htmlBody,
                $textBody ?: strip_tags($htmlBody),
                null, // tag
                true, // trackOpens
                null, // replyTo
                null, // cc
                null, // bcc
                null, // headers
                null, // attachments
                'None', // trackLinks
                null, // metadata
                $messageStream
            );
            return $sendResult['ErrorCode'] === 0;
        } catch (\Exception $e) {
            // Optionally log $e->getMessage()
            return false;
        }
    }
}
