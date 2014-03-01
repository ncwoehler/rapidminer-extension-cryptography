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
package com.rapidminer.cryptography;

import java.util.LinkedList;
import java.util.List;

import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEByteEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;

import com.rapidminer.operator.Operator;
import com.rapidminer.parameter.ParameterType;
import com.rapidminer.parameter.ParameterTypeCategory;
import com.rapidminer.parameter.ParameterTypePassword;
import com.rapidminer.parameter.UndefinedParameterError;
import com.rapidminer.parameter.conditions.EqualTypeCondition;

/**
 * This class is used for providing parameters used for password based
 * encryption/decryption algorithms like passwords, algorithm, etc. These
 * parameters are then being used to configure a Byte or String encryptor.
 * 
 * @author Nils Woehler
 * 
 */
public class PBEncryptorConfigurator {

	public static final String PARAMETER_PASSWORD = "password";

	public static final String PARAMETER_ALGORITHM_STRENGTH = "algorithm_strength";
	public static final String WEAK_ALGORITHM = "weak";
	public static final String MEDIUM_ALGORITHM = "medium";
	public static final String STRONG_ALGORITHM = "strong";
	public static final String USER_DEFINED_ALGORITHM = "user defined";
	public static final String[] ALGORITHM_STRENGTHS = new String[] {
			WEAK_ALGORITHM, MEDIUM_ALGORITHM, STRONG_ALGORITHM,
			USER_DEFINED_ALGORITHM };
	public static final int USER_DEFINED_ALGORITHM_INDEX = 3;

	public static final String PARAMETER_ALGORITHM = "algorithm";

	public static final String WEAK_ALGORITHM_NAME = "PBEWITHSHA1ANDRC2";
	public static final String MEDIUM_ALGORITHM_NAME = "PBEWITHMD5AND256BITAES-CBC-OPENSSL";
	public static final String STRONG_ALGORITHM_NAME = "PBEWITHSHA256AND256BITAES-CBC-BC";

	// presented user defined algorithm in user friendly fashion
	public static final String DEFAULT_USER_ALGORITHM_NAME = "MD5 and 256BITAES-CBC-OPENSSL";

	/**
	 * Creates a byte encryptor according to the specified parameters.
	 */
	public PBEByteEncryptor configureByteEncryptor(Operator op)
			throws UndefinedParameterError {
		PooledPBEByteEncryptor encryptor = new PooledPBEByteEncryptor();
		encryptor.setAlgorithm(getAlgorithm(op));
		encryptor.setPassword(op.getParameterAsString(PARAMETER_PASSWORD));
		encryptor.setProvider(BCAlgorithmProvider.INSTANCE.getProvider());
		return encryptor;
	}

	/**
	 * Creates a string encryptor according to the specified parameters.
	 */
	public PBEStringEncryptor configureStringEncryptor(Operator op)
			throws UndefinedParameterError {
		PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
		encryptor.setAlgorithm(getAlgorithm(op));
		encryptor.setPassword(op.getParameterAsString(PARAMETER_PASSWORD));
		encryptor.setProvider(BCAlgorithmProvider.INSTANCE.getProvider());
		return encryptor;
	}

	private String getAlgorithm(Operator op) throws UndefinedParameterError {
		switch (op.getParameter(PARAMETER_ALGORITHM_STRENGTH)) {
		case WEAK_ALGORITHM:
			return WEAK_ALGORITHM_NAME;
		case MEDIUM_ALGORITHM:
			return MEDIUM_ALGORITHM_NAME;
		case STRONG_ALGORITHM:
			return STRONG_ALGORITHM_NAME;
		default:
			return BCAlgorithmProvider.toAlgorithmID(op
					.getParameterAsString(PARAMETER_ALGORITHM));
		}
	}

	/**
	 * @return the list of parameter types used to configure an encryptor
	 */
	public List<ParameterType> getParameterTypes(Operator op) {
		List<ParameterType> types = new LinkedList<>();

		ParameterTypePassword password = new ParameterTypePassword(
				PARAMETER_PASSWORD,
				"The password used to encrypt/decrypt the file.");
		password.setOptional(false);
		password.setExpert(true);
		types.add(password);

		types.add(new ParameterTypeCategory(
				PARAMETER_ALGORITHM_STRENGTH,
				"Defines the algorithm strength used for  encryption/decryption.",
				ALGORITHM_STRENGTHS, 1, false));

		List<Object> suggestions = BCAlgorithmProvider.INSTANCE
				.getPBEAlgorithms();

		ParameterTypeCategory suggestion = new ParameterTypeCategory(
				PARAMETER_ALGORITHM,
				"The algorithm used to encrypt/decrypt the file.",
				suggestions.toArray(new String[suggestions.size()]),
				suggestions.indexOf(DEFAULT_USER_ALGORITHM_NAME));
		suggestion.registerDependencyCondition(new EqualTypeCondition(op,
				PARAMETER_ALGORITHM_STRENGTH, ALGORITHM_STRENGTHS, true,
				USER_DEFINED_ALGORITHM_INDEX));
		types.add(suggestion);

		return types;
	}

}
