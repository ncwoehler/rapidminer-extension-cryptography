/*
 *  RapidMiner Cryptography Extension
 *
 *  Copyright (C) 2014 by Nils Woehler
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see http://www.gnu.org/licenses/.
 */
package com.rapidminer.tools.expression.parser;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.RuntimeCryptoException;
import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.jasypt.digest.PooledByteDigester;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

/**
 * A container class executing the digest and matching functions. It contains a
 * cache for already created digesters and reuses them avoid object creation for
 * each new example value input.
 * 
 * @author Nils Woehler
 * 
 */
enum Digester {

	INSTANCE;

	// BASE64 encoder which will make sure the returned digests are
	// valid US-ASCII strings.
	// The Base64 encoder is THREAD-SAFE
	private final Base64 BASE64 = new Base64();

	// Charset to create String from base64 encoded byte array
	private final String HASH_CHARSET = "US-ASCII";

	/**
	 * Cache for digesters that can be reused for the same digester configs.
	 */
	private final Map<DigesterConfig, PooledByteDigester> DIGESTERS = new HashMap<>();

	/**
	 * Converts the provided value to a base64 encoded hash representation. The
	 * conversion is done by converting the value to byte[] on which the hash
	 * function is applied.
	 */
	protected String digest(Object value, DigesterConfig config)
			throws JEPFunctionException {

		// convert input to byte array
		byte[] bytes = getBytes(value);

		// digest input array
		byte[] digested;
		try {
			digested = getDigester(config).digest(bytes);
		} catch (EncryptionOperationNotPossibleException e) {
			throw new JEPFunctionException(
					"Error while calculating hash. Check if your system does support the selected hash algorithm.");
		}

		// base64 encode digested array and return result
		try {
			return new String(BASE64.encode(digested), HASH_CHARSET);
		} catch (UnsupportedEncodingException e) {
			// cannot happen
			throw new RuntimeCryptoException(e.getLocalizedMessage());
		}

	}

	/**
	 * Checks wether the provided value matches the base64 encoded hash value.
	 * This has to be done with the same settings that have been used to
	 * calculcate the base64 encoded value.
	 */
	protected boolean matches(Object value, String base64Hash,
			DigesterConfig config) throws JEPFunctionException {

		try {
			// convert input to byte array
			byte[] bytes = getBytes(value);

			// base64 sanity check
			byte[] hashBytes = base64Hash.getBytes(HASH_CHARSET);
			if (!Base64.isArrayByteBase64(hashBytes)) {
				throw new JEPFunctionException(
						"Hash value is not base64 encoded. Value and hash arguments switched? (First value than hash)");
			}

			// decode hash value to bytes
			hashBytes = BASE64.decode(hashBytes);

			PooledByteDigester digester = getDigester(config);
			return digester.matches(bytes, hashBytes);
		} catch (EncryptionOperationNotPossibleException e) {
			throw new JEPFunctionException(
					"Error while hash is being matched. Check if second argument truely is a base64 encoded hash "
							+ " and if your system does support the selected hash algorithm.");
		} catch (UnsupportedEncodingException e) {
			// cannot happen
			throw new RuntimeCryptoException(e.getLocalizedMessage());
		}
	}

	/**
	 * @param config
	 *            the {@link DigesterConfig} which is used as hash key for the
	 *            digester cache.
	 * @return a {@link PooledByteDigester} for the specified config. For each
	 *         config configuration one digester is created and cached. The
	 *         digesters can be re-used as they are thread-safe.
	 */
	private PooledByteDigester getDigester(DigesterConfig config)
			throws JEPFunctionException {
		PooledByteDigester digester = DIGESTERS.get(config);

		// in case digester for config is not created yet,
		// create a new one, configure, initialize and cache it
		if (digester == null) {
			digester = new PooledByteDigester();
			digester.setConfig(config.toDigesterConfig());
			try {
				digester.initialize();
			} catch (EncryptionInitializationException e) {
				throw new JEPFunctionException(
						"Error initializing hash function. The selected hash function might not be supported by your system.");
			}
			DIGESTERS.put(config, digester);
		}
		return digester;
	}

	/**
	 * Converts an {@link Object} to a byte[]. The value has to be an instance
	 * of String, Integer, Long, Float, Date or Double.
	 * 
	 * @throws JEPFunctionException
	 *             in case the object class is unknown.
	 */
	private byte[] getBytes(Object value) throws JEPFunctionException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				DataOutputStream dos = new DataOutputStream(baos);) {
			if (value instanceof String) {
				dos.writeUTF((String) value);
			} else if (value instanceof Integer) {
				dos.writeInt((int) value);
			} else if (value instanceof Long) {
				dos.writeLong((long) value);
			} else if (value instanceof Float) {
				dos.writeFloat((float) value);
			} else if (value instanceof Date) {
				dos.writeLong(((Date) value).getTime());
			} else if (value instanceof Double) {
				dos.writeDouble((double) value);
			} else {
				// should not happen
				throw new JEPFunctionException("Unknown input type: "
						+ value.getClass());
			}
			return baos.toByteArray();
		} catch (Throwable t) {
			throw new JEPFunctionException("Error calculating hash value: "
					+ t.getLocalizedMessage());
		}
	}
}
