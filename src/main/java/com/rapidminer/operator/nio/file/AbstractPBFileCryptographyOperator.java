/*
 *  RapidMiner Encryption Extension
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
package com.rapidminer.operator.nio.file;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

import com.rapidminer.operator.Operator;
import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.OperatorException;
import com.rapidminer.operator.PBCryptographyConfigurator;
import com.rapidminer.operator.ProcessSetupError.Severity;
import com.rapidminer.operator.SimpleProcessSetupError;
import com.rapidminer.operator.UserError;
import com.rapidminer.operator.ports.InputPort;
import com.rapidminer.operator.ports.OutputPort;
import com.rapidminer.operator.ports.Port;
import com.rapidminer.operator.ports.metadata.MDTransformationRule;
import com.rapidminer.parameter.ParameterType;
import com.rapidminer.parameter.ParameterTypeBoolean;
import com.rapidminer.parameter.PortProvider;
import com.rapidminer.parameter.UndefinedParameterError;
import com.rapidminer.tools.Tools;

/**
 * The abstract super class for all PBE file encryption/decryption operators.
 * The operator has a file input and a file output. Furthermore the user is able
 * to select the algorithm strength and password.
 * 
 * @author Nils Woehler
 * 
 */
public abstract class AbstractPBFileCryptographyOperator extends Operator {

	public static final String PARAMETER_FILE_INPUT = "file_input";
	public static final String PARAMETER_FILE_OUTPUT = "file_output";
	public static final String PARAMETER_BASE64 = "base64";
	public static final String PARAMETER_OVERRIDE = "override";

	private final InputPort fileInput = getInputPorts()
			.createPort("file input");
	private final FileInputPortHandler filePortHandler = new FileInputPortHandler(
			this, fileInput, PARAMETER_FILE_INPUT);

	private final OutputPort fileOutput = getOutputPorts().createPort(
			"file output");
	private final FileOutputPortHandler fileOutputHandler = new FileOutputPortHandler(
			this, fileOutput, PARAMETER_FILE_OUTPUT);

	/**
	 * Used to test if encryption works with the current parameters.
	 */
	private static final byte[] RANDOM_BYTES = new byte[] { 81, 79, 11, 28, 64,
			42, 41 };

	private static final PBCryptographyConfigurator ALGORITHM_PROVIDER = new PBCryptographyConfigurator();

	public AbstractPBFileCryptographyOperator(OperatorDescription description) {
		super(description);

		getTransformer().addRule(new MDTransformationRule() {

			@Override
			public void transformMD() {
				try {
					StandardPBEByteEncryptor encryptor = configureEncryptor();
					encryptor.decrypt(encryptor.encrypt(RANDOM_BYTES));
				} catch (Throwable t) {
					addError(new SimpleProcessSetupError(Severity.ERROR,
							getPortOwner(), "file.encryption_error", t
									.getLocalizedMessage()));
				}
			}

		});
		getTransformer().addPassThroughRule(fileInput, fileOutput);
	}

	@Override
	public void doWork() throws OperatorException {

		// first check if output file exists and if overriding is allowed
		if (isParameterSet(PARAMETER_FILE_OUTPUT)
				&& getParameterAsFile(PARAMETER_FILE_OUTPUT).exists()
				&& !getParameterAsBoolean(PARAMETER_OVERRIDE)) {
			throw new UserError(this, "file.output_file_already_exists");
		}

		// read input file
		byte[] fileContent = readInputFile();

		// in case of decryption and base64 encoding, decode first
		if (!isEncrypting() && getParameterAsBoolean(PARAMETER_BASE64)) {
			try {
				fileContent = Base64.decode(fileContent);
			} catch (DecoderException e) {
				throw new UserError(this, e, "file.base64_decoding_failed");
			}
		}

		// transform file
		fileContent = transformFile(configureEncryptor(), fileContent);

		// in case of encryption and base64 encoding, decode encrypted output
		if (isEncrypting() && getParameterAsBoolean(PARAMETER_BASE64)) {
			try {
				fileContent = Base64.encode(fileContent);
			} catch (DecoderException e) {
				throw new UserError(this, e, "file.base64_encoding_failed");
			}
		}

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

	/**
	 * Creates and configures a byte encryptor.
	 */
	protected StandardPBEByteEncryptor configureEncryptor()
			throws UndefinedParameterError {
		return ALGORITHM_PROVIDER.configureByteEncryptor(this);
	}

	/**
	 * Transforms the input, e.g. encrypts or decrypts it with the provided
	 * {@link StandardPBEByteEncryptor}.
	 * 
	 * @param encryptor
	 *            the encryptor being used
	 * @param fileContent
	 *            the content being encrypted/decrypted
	 * @return the encrypted/decrypted content
	 */
	protected abstract byte[] transformFile(StandardPBEByteEncryptor encryptor,
			byte[] fileContent) throws UserError;

	/**
	 * Reads input from input file and returns it as byte array.
	 */
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
				getParameterHandler(), PARAMETER_FILE_INPUT, null,
				new PortProvider() {

					@Override
					public Port getPort() {
						return fileInput;
					}
				}));

		parameterTypes.addAll(ALGORITHM_PROVIDER.getParameterTypes(this));

		parameterTypes.add(new ParameterTypeBoolean(PARAMETER_BASE64,
				"If checked the output will be Base64 encoded.", false, true));

		parameterTypes.add(FileOutputPortHandler.makeFileParameterType(
				getParameterHandler(), PARAMETER_FILE_OUTPUT,
				new PortProvider() {

					@Override
					public Port getPort() {
						return fileOutput;
					}
				}));

		parameterTypes.add(new ParameterTypeBoolean(PARAMETER_OVERRIDE,
				"If checked an already existing file will be overwritten.",
				false, false));

		return parameterTypes;
	}

	protected abstract boolean isEncrypting();
}
