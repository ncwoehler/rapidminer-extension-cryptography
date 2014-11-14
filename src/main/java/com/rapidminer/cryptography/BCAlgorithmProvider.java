/**
 * RapidMiner Cryptography Extension
 *
 * Copyright (C) 2014-2014 by Nils Woehler
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
package com.rapidminer.cryptography;

import java.security.Provider;
import java.security.Provider.Service;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

/**
 * Enum for accessing the BC provider.
 * 
 * @author Nils Woehler
 *
 */
public enum BCAlgorithmProvider {

	INSTANCE;
	
	/**
	 * The BouncyCastle provider being returned by {@link #getProvider()}.
	 */
	private final BouncyCastleProvider provider = new BouncyCastleProvider();

	/**
	 * @return the provider for bouncy castle algorithms
	 */
	public BouncyCastleProvider getProvider() {
		return provider;
	}
	
	/**
	 * Used to test if encryption works with the current parameters.
	 */
	private static final byte[] RANDOM_BYTES = new byte[] { 81, 79, 11, 28, 64,
			42, 41 };

	private static final String PBE = "PBE";
	private List<Object> algorithms = null;

	public synchronized List<Object> getPBEAlgorithms() {
		if (algorithms == null) {
			algorithms = getSupportedAlgorithms();
		}
		return algorithms;
	}

	/**
	 * @return all currently installed algorithm names that can be used to
	 *         create a cipher
	 */
	private static List<Object> getSupportedAlgorithms() {
		Set<String> algorithmNames = new HashSet<>();
		Provider provider = BCAlgorithmProvider.INSTANCE.getProvider();
		for (Service service : provider.getServices()) {
			// only add algorithms that start with PBE (password based
			// encryption) and work for Cipher and KeyGenerator..
			if (service.getAlgorithm().startsWith(PBE)) {
				try {
					StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
					encryptor.setProvider(provider);
					encryptor.setPassword("asdfghjkl");
					encryptor.setAlgorithm(service.getAlgorithm());
					encryptor.decrypt(encryptor.encrypt(RANDOM_BYTES));

					// only add algorithms with cipher and secret key
					// factories
					algorithmNames
							.add(toHumandReadable(service.getAlgorithm()));
				} catch (Throwable t) {
					// do nothing
				}
			}
		}
		List<String> sortedAlgorithmNameList = new LinkedList<String>(
				algorithmNames);
		Collections.sort(sortedAlgorithmNameList, Collections.reverseOrder());
		return new ArrayList<Object>(sortedAlgorithmNameList);
	}

	/**
	 * @return all currently installed hash functions that can be used to create
	 *         a hash
	 */
	public List<String> getHashFunctions() {
		List<String> algos = new ArrayList<String>();
		for(Service service : BCAlgorithmProvider.INSTANCE.getProvider().getServices()) {
			if("MessageDigest".equals(service.getType())) {
				algos.add(service.getAlgorithm());
			}
		}
		Collections.sort(algos);
		return algos;
	}

	public int getDefaultHashFunction() {
		return getHashFunctions().indexOf("MD5");
	}
	
	/**
	 * Converts the algorithm ID into human readable by removing the leading
	 * 'PBEWITH' and replacing AND by ' and '.
	 */
	public static final String toHumandReadable(String algorithmName) {
		return algorithmName.substring(7).replaceFirst("AND", " and ");
	}

	/**
	 * Converts a human readable algorithm back to the algorithm ID format that
	 * is being used to select algorithms from the BouncyCastle provider.
	 */
	public static final String toAlgorithmID(String humandReadable) {
		return "PBEWITH" + humandReadable.replaceFirst(" and ", "AND");
	}

}
