/*
 * Copyright (C) 2001-2014 RapidMiner GmbH
 */
package com.rapidminer.operator.nio.file;

import com.rapidminer.operator.Operator;
import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.OperatorException;
import com.rapidminer.operator.UserError;
import com.rapidminer.operator.ports.InputPort;
import com.rapidminer.operator.ports.OutputPort;
import com.rapidminer.operator.ports.Port;
import com.rapidminer.parameter.ParameterType;
import com.rapidminer.parameter.ParameterTypeCategory;
import com.rapidminer.parameter.ParameterTypePassword;
import com.rapidminer.parameter.PortProvider;
import com.rapidminer.tools.Tools;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 * This operator takes a file as input and encrypts in according with the specified algorithm and
 * password. For encryption algorithms from java.security are being used.
 * 
 * @author Nils Woehler
 * 
 */
public class DecryptFileOperator extends Operator {

	public static final String PARAMETER_FILE_INPUT = "file_input";
	public static final String PARAMETER_FILE_OUTPUT = "file_output";
	public static final String PARAMETER_PASSWORD = "password";
	public static final String PARAMETER_CIPHER = "algorithm";

	public static final String DEFAULT_ALGORITHM = "RSA";

	private final InputPort fileInput = getInputPorts().createPort("file input");
	private final FileInputPortHandler filePortHandler = new FileInputPortHandler(this, fileInput, PARAMETER_FILE_INPUT);

	private final OutputPort fileOutput = getOutputPorts().createPort("file output");
	private final FileOutputPortHandler fileOutputHandler = new FileOutputPortHandler(this, fileOutput,
			PARAMETER_FILE_OUTPUT);

	public DecryptFileOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	public void doWork() throws OperatorException {

		// open input stream
		try (InputStream fileInput = filePortHandler.openSelectedFile()) {
			String password = getParameterAsString(PARAMETER_PASSWORD);

			// open output stream
			try (OutputStream fileOutput = fileOutputHandler.openSelectedFile()) {

				// create cipher
				String cipherName = getParameterAsString(PARAMETER_CIPHER);
				Cipher c;
				try {
					c = Cipher.getInstance(cipherName);
				} catch (NoSuchAlgorithmException e) {
					// might happen in case the process was configured on a machine was more
					// algorithms available
					throw new UserError(this, e, "invalid_cipher_algorithm");
				} catch (NoSuchPaddingException e) {
					// should not happen
					throw new UserError(this, e, "invalid_cipher_padding");
				}
				Key k = new SecretKeySpec(password.getBytes(Charset.forName("UTF-8")), cipherName);
				try {
					c.init(Cipher.ENCRYPT_MODE, k);
				} catch (InvalidKeyException e) {
					throw new UserError(this, e, "invalid_cipher_key");
				}

				// open encrypted output stream and copy stream synchronously
				try (OutputStream encryptedFileStream = new CipherOutputStream(fileOutput, c)) {
					Tools.copyStreamSynchronously(fileInput, encryptedFileStream, true);
				}
			}
		} catch (IOException e) {
			throw new UserError(this, e, 303, getParameterAsFile(PARAMETER_FILE_INPUT), e.getMessage());
		}
	}

	@Override
	public List<ParameterType> getParameterTypes() {
		List<ParameterType> parameterTypes = super.getParameterTypes();
		parameterTypes.add(FileInputPortHandler.makeFileParameterType(getParameterHandler(), PARAMETER_FILE_INPUT,
				"The file that should be encrypted.", new PortProvider() {

					@Override
					public Port getPort() {
						return fileInput;
					}
				}));
		parameterTypes.add(new ParameterTypePassword(PARAMETER_PASSWORD, "The password used to encrypt the file"));
		parameterTypes.add(new ParameterTypeCategory(PARAMETER_CIPHER,
				"The algorithm that should be used to encrypt the file.", getSupportedAlgorithms(),
				getDefaultAlgorithmIndex()));

		parameterTypes.add(FileOutputPortHandler.makeFileParameterType(getParameterHandler(), PARAMETER_FILE_OUTPUT,
				new PortProvider() {

					@Override
					public Port getPort() {
						return fileOutput;
					}
				}));
		return parameterTypes;
	}

	/**
	 * @return all currently installed algorithm names that can be used to create a cipher
	 */
	private static String[] getSupportedAlgorithms() {
		List<String> algorithmNames = new LinkedList<>();
		for (Provider provider : Security.getProviders()) {
			algorithmNames.add(provider.getName());
		}
		return algorithmNames.toArray(new String[algorithmNames.size()]);
	}

	/**
	 * @return the index for RSA algorithm
	 */
	private static int getDefaultAlgorithmIndex() {
		String[] algorithmNames = getSupportedAlgorithms();
		int index = 0;
		for (String algoName : algorithmNames) {
			if (DEFAULT_ALGORITHM.equals(algoName)) {
				return index;
			}
			++index;
		}
		return index;
	}
}
