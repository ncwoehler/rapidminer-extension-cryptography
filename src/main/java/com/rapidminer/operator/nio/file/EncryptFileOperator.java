/*
 * Copyright (C) 2001-2014 RapidMiner GmbH
 */
package com.rapidminer.operator.nio.file;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

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
import com.rapidminer.tools.LogService;
import com.rapidminer.tools.Tools;

/**
 * This operator takes a file as input and encrypts in according with the
 * specified algorithm and password. For encryption algorithms from
 * java.security are being used.
 * 
 * @author Nils Woehler
 * 
 */
public class EncryptFileOperator extends Operator {

	public static final String PARAMETER_FILE_INPUT = "file_input";
	public static final String PARAMETER_FILE_OUTPUT = "file_output";
	public static final String PARAMETER_PASSWORD = "password";
	public static final String PARAMETER_ALGORITHM = "algorithm";

	public static final String DEFAULT_ALGORITHM = "RSA";

	private final InputPort fileInput = getInputPorts()
			.createPort("file input");
	private final FileInputPortHandler filePortHandler = new FileInputPortHandler(
			this, fileInput, PARAMETER_FILE_INPUT);

	private final OutputPort fileOutput = getOutputPorts().createPort(
			"file output");
	private final FileOutputPortHandler fileOutputHandler = new FileOutputPortHandler(
			this, fileOutput, PARAMETER_FILE_OUTPUT);

	// The internal encryptor
	private final StandardPBEByteEncryptor encryptor;

	public EncryptFileOperator(OperatorDescription description) {
		super(description);
		encryptor = new StandardPBEByteEncryptor();
	}

	@Override
	public void doWork() throws OperatorException {

		// read input file
		byte[] fileContent = readInputFile();

		encryptor.setAlgorithm(getParameterAsString(PARAMETER_ALGORITHM));
		encryptor.setPassword(getParameterAsString(PARAMETER_PASSWORD));

		// encrypt file
		fileContent = encryptor.encrypt(fileContent);

		// write encrypted file to output
		try (OutputStream fileOutput = fileOutputHandler.openSelectedFile()) {
			ByteArrayInputStream byteInput = new ByteArrayInputStream(
					fileContent);
			Tools.copyStreamSynchronously(byteInput, fileOutput, true);
		} catch (IOException e) {
			throw new UserError(this, e, 303,
					getParameterAsFile(PARAMETER_FILE_OUTPUT), e.getMessage());
		}
	}

	private byte[] readInputFile() throws OperatorException {
		// open input stream
		try (InputStream fs = filePortHandler.openSelectedFile()) {
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();

			int nRead;
			byte[] data = new byte[16384];

			while ((nRead = fs.read(data, 0, data.length)) != -1) {
				buffer.write(data, 0, nRead);
			}

			buffer.flush();

			return buffer.toByteArray();
		} catch (IOException e) {
			throw new UserError(this, e, 303,
					getParameterAsFile(PARAMETER_FILE_INPUT), e.getMessage());
		}
	}

	@Override
	public List<ParameterType> getParameterTypes() {
		List<ParameterType> parameterTypes = super.getParameterTypes();
		parameterTypes.add(FileInputPortHandler.makeFileParameterType(
				getParameterHandler(), PARAMETER_FILE_INPUT,
				"The file that should be encrypted.", new PortProvider() {

					@Override
					public Port getPort() {
						return fileInput;
					}
				}));
		parameterTypes.add(new ParameterTypePassword(PARAMETER_PASSWORD,
				"The password used to encrypt the file"));
		parameterTypes.add(new ParameterTypeCategory(PARAMETER_ALGORITHM,
				"The algorithm that should be used to encrypt the file.",
				getSupportedAlgorithms(), getDefaultAlgorithmIndex()));

		parameterTypes.add(FileOutputPortHandler.makeFileParameterType(
				getParameterHandler(), PARAMETER_FILE_OUTPUT,
				new PortProvider() {

					@Override
					public Port getPort() {
						return fileOutput;
					}
				}));
		return parameterTypes;
	}

	/**
	 * @return all currently installed algorithm names that can be used to
	 *         create a cipher
	 */
	private static String[] getSupportedAlgorithms() {
		List<String> algorithmNames = new LinkedList<>();
		for (Provider provider : Security.getProviders()) {
			for (Service service : provider.getServices()) {
				// only add cipher algorithms
				if ("cipher".equals(service.getType().toLowerCase(Locale.US))) {
					algorithmNames.add(service.getAlgorithm());
				}
			}
		}
		return algorithmNames.toArray(new String[algorithmNames.size()]);
	}

	/**
	 * @return the index for RSA algorithm
	 */
	private static int getDefaultAlgorithmIndex() {
		int indexOfRSA = Arrays.asList(getSupportedAlgorithms()).indexOf(
				DEFAULT_ALGORITHM);
		if (indexOfRSA >= 0) {
			return indexOfRSA;
		} else {
			LogService.getRoot().log(
					Level.CONFIG,
					"Default cipher algorithm not found, using "
							+ getSupportedAlgorithms()[0] + " instead."); // TODO
																			// I18N
			return 0;
		}
	}
}
