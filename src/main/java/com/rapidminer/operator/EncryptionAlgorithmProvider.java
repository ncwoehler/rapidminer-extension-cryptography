package com.rapidminer.operator;

import java.util.LinkedList;
import java.util.List;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import com.rapidminer.parameter.ParameterType;
import com.rapidminer.parameter.ParameterTypePassword;
import com.rapidminer.parameter.ParameterTypeSuggestion;
import com.rapidminer.parameter.UndefinedParameterError;

public class EncryptionAlgorithmProvider {

	public static final String PARAMETER_PASSWORD = "password";
	public static final String PARAMETER_ALGORITHM = "algorithm";

	/**
	 * Creates a byte encryptor according to the specified parameters.
	 */
	public StandardPBEByteEncryptor configureByteEncryptor(Operator op)
			throws UndefinedParameterError {
		StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
		encryptor.setAlgorithm(op.getParameterAsString(PARAMETER_ALGORITHM));
		encryptor.setPassword(op.getParameterAsString(PARAMETER_PASSWORD));
		return encryptor;
	}

	/**
	 * Creates a string encryptor according to the specified parameters.
	 */
	public StandardPBEStringEncryptor configureStringEncryptor(Operator op)
			throws UndefinedParameterError {
		StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
		encryptor.setAlgorithm(op.getParameterAsString(PARAMETER_ALGORITHM));
		encryptor.setPassword(op.getParameterAsString(PARAMETER_PASSWORD));
		return encryptor;
	}

	/**
	 * @return the list of parameter types used to configure an encryptor
	 */
	public List<ParameterType> getParameterTypes() {
		List<ParameterType> types = new LinkedList<>();

		ParameterTypePassword password = new ParameterTypePassword(
				PARAMETER_PASSWORD,
				"The password used to encrypt/decrypt the file.");
		password.setOptional(false);
		password.setExpert(true);
		types.add(password);

		// TODO add category parameter type with (weak, medium, strong, user
		// selection) categories

		types.add(new ParameterTypeSuggestion(PARAMETER_ALGORITHM,
				"The algorithm used to encrypt/decrypt the file.",
				AlgorithmSuggestionProvider.INSTANCE,
				StandardPBEByteEncryptor.DEFAULT_ALGORITHM, false));

		return types;
	}

}
