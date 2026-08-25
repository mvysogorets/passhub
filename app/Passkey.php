<?php

/**
 * Passkey.php
 *
 * PHP version 7
 *
 * @category  Password_Manager
 * @package   PassHub
 * @author    Mikhail Vysogorets <m.vysogorets@wwpass.com>, Ann Savoy
 * @copyright 2026 WWPass
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

namespace PassHub;

class Passkey
{
    /**
     * Validate the structure of a passkey
     * 
     * @param object $passkey Passkey data to validate
     * @return array Validation result ['valid' => bool, 'error' => string]
     */
    public static function validate($passkey)
    {
        if (!is_object($passkey)) {
            return ['valid' => false, 'error' => 'Passkey must be an object'];
        }

        $required_fields = [
            'credentialId' => 'string',
            'privateKey' => 'string',
            'publicKey' => 'string',
            'userHandle' => 'string',
            'counter' => 'integer',
            'rpId' => 'string'
        ];

        foreach ($required_fields as $field => $type) {
            if (!isset($passkey->$field)) {
                return ['valid' => false, 'error' => "Missing required field: $field"];
            }

            if ($type === 'string' && !is_string($passkey->$field)) {
                return ['valid' => false, 'error' => "Field $field must be a string"];
            }

            if ($type === 'integer' && !is_int($passkey->$field)) {
                return ['valid' => false, 'error' => "Field $field must be an integer"];
            }
        }

        // Validate rpId (must be a valid domain)
        if (!self::isValidRpId($passkey->rpId)) {
            return ['valid' => false, 'error' => 'Invalid rpId format'];
        }

        return ['valid' => true, 'error' => null];
    }

    /**
     * Check the validity of rpId (domain)
     * 
     * @param string $rpId Relying Party ID to check
     * @return bool
     */
    private static function isValidRpId($rpId)
    {
        // Basic domain validation
        return preg_match('/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i', $rpId) === 1;
    }

    /**
     * Get passkeys for a specific rpId
     * 
     * @param object $mng MongoDB connection
     * @param string $UserID User ID
     * @param string $rpId Relying Party ID
     * @return array Array of passkeys for the given rpId
     */
    public static function getPasskeysForRpId($mng, $UserID, $rpId)
    {
        // Get all Safes for the user
        $cursor = $mng->safe_users->find(['UserID' => $UserID]);
        $safeUsers = $cursor->toArray();

        $passkeys = [];

        foreach ($safeUsers as $safeUser) {
            $SafeID = $safeUser->SafeID;

            // Find all passkeys in this Safe for the given rpId
            $itemsCursor = $mng->safe_items->find([
                'SafeID' => $SafeID,
                'version' => 6,
                'type' => 'passkey',
                'passkey.rpId' => $rpId
            ]);

            $items = $itemsCursor->toArray();

            foreach ($items as $item) {
                $passkeys[] = [
                    '_id' => (string)$item->_id,
                    'SafeID' => $SafeID,
                    'data' => $item->data,
                    'iv' => $item->iv,
                    'tag' => $item->tag,
                    'passkey' => $item->passkey,
                    'encrypted_key' => $safeUser->encrypted_key ?? null,
                    'encrypted_key_CSE' => $safeUser->encrypted_key_CSE ?? null
                ];
            }
        }

        return $passkeys;
    }

    /**
     * Increment the counter for a passkey (protection against replay attacks)
     * 
     * @param object $mng MongoDB connection
    * @param string $UserID Current user ID
    * @param string $itemId Passkey item ID
     * @return bool Operation success
     */
    public static function incrementCounter($mng, $UserID, $itemId)
    {
        try {
            $safeUsers = $mng->safe_users->find(['UserID' => $UserID]);
            $safeIds = [];
            foreach ($safeUsers as $safeUser) {
                $safeIds[] = $safeUser->SafeID;
            }
            if (count($safeIds) === 0) {
                return false;
            }

            $result = $mng->safe_items->updateOne(
                [
                    '_id' => new \MongoDB\BSON\ObjectID($itemId),
                    'SafeID' => ['$in' => $safeIds],
                    'version' => 6,
                    'type' => 'passkey'
                ],
                ['$inc' => ['passkey.counter' => 1]]
            );

            return $result->getModifiedCount() === 1;
        } catch (\Exception $e) {
            Utils::err("Error incrementing passkey counter: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Create a structure for a new passkey
     * 
     * @param string $siteName Site name
     * @param string $username Username/Email
     * @param string $rpId Relying Party ID
     * @param string $notes Notes
     * @return array Cleartext structure for the passkey
     */
    public static function createCleartext($siteName, $username, $rpId, $notes = '')
    {
        return [
            $siteName,
            $username,
            $rpId,
            $notes
        ];
    }

    /**
     * Extract URL from rpId for display
     * 
     * @param string $rpId Relying Party ID
     * @return string URL in the format https://
     */
    public static function rpIdToUrl($rpId)
    {
        return 'https://' . $rpId;
    }

    /**
     * Get statistics for a user's passkeys
     * 
     * @param object $mng MongoDB connection
     * @param string $UserID User ID
     * @return array Statistics ['total' => int, 'by_rpId' => array]
     */
    public static function getStats($mng, $UserID)
    {
        $cursor = $mng->safe_users->find(['UserID' => $UserID]);
        $safeUsers = $cursor->toArray();

        $total = 0;
        $byRpId = [];

        foreach ($safeUsers as $safeUser) {
            $SafeID = $safeUser->SafeID;

            $itemsCursor = $mng->safe_items->find([
                'SafeID' => $SafeID,
                'version' => 6,
                'type' => 'passkey'
            ]);

            $items = $itemsCursor->toArray();

            foreach ($items as $item) {
                $total++;
                $rpId = $item->passkey->rpId ?? 'unknown';
                if (!isset($byRpId[$rpId])) {
                    $byRpId[$rpId] = 0;
                }
                $byRpId[$rpId]++;
            }
        }

        return [
            'total' => $total,
            'by_rpId' => $byRpId
        ];
    }
}
