package com.rapidminer.operator.nio.file;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.List;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import com.rapidminer.operator.PBEAlgorithmParameterHandler;
import com.rapidminer.operator.Operator;
import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.OperatorException;
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
 * This operator takes a file as input and encrypts it to according the
 * specified algorithm and password. Password based algorithms are taken from
 * providers registered to {@link Security}.
 * 
 * @author Nils Woehler
 * 
 */
public abstract class AbstractPBFileEncryptionOperator extends Operator {

	public static final String PARAMETER_FILE_INPUT = "file_input";
	public static final String PARAMETER_FILE_OUTPUT = "file_output";
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

	private static final PBEAlgorithmParameterHandler ALGORITHM_PROVIDER = new PBEAlgorithmParameterHandler();

	public AbstractPBFileEncryptionOperator(OperatorDescription description) {
		super(description);

		getTransformer().addRule(new MDTransformationRule() {

			@Override
			public void transformMD() {
				try {
					StandardPBEByteEncryptor encryptor = configureEncryptor();
					encryptor.decrypt(encryptor.encrypt(RANDOM_BYTES));
				} catch (Throwable t) {
					addError(new SimpleProcessSetupError(Severity.ERROR,
							getPortOwner(), "file_encryption_error", t
									.getLocalizedMessage()));
				}
			}

		});
	}

	@Override
	public void doWork() throws OperatorException {

		// first check if output file exists and if overriding is allowed
		if (isParameterSet(PARAMETER_FILE_OUTPUT)
				&& getParameterAsFile(PARAMETER_FILE_OUTPUT).exists()
				&& !getParameterAsBoolean(PARAMETER_OVERRIDE)) {
			throw new UserError(this, "output_file_already_exists");
		}

		// read input file
		byte[] fileContent = readInputFile();

		// transform file
		try {
			fileContent = transformFile(configureEncryptor(), fileContent);
		} catch (EncryptionOperationNotPossibleException
				| EncryptionInitializationException e) {
			throw new UserError(this, e, "encryption_not_possible");
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
	protected StandardPBEByteEncryptor configureEncryptor() throws UndefinedParameterError {
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
				false));
		return parameterTypes;
	}
}
