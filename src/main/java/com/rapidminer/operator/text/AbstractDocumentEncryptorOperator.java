package com.rapidminer.operator.text;

import java.security.Security;
import java.util.List;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import com.rapidminer.operator.EncryptionAlgorithmProvider;
import com.rapidminer.operator.Operator;
import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.OperatorException;
import com.rapidminer.operator.ProcessSetupError.Severity;
import com.rapidminer.operator.SimpleProcessSetupError;
import com.rapidminer.operator.UserError;
import com.rapidminer.operator.ports.metadata.MDTransformationRule;
import com.rapidminer.parameter.ParameterType;
import com.rapidminer.parameter.UndefinedParameterError;

/**
 * This operator takes a document as input and encrypts it to according the
 * specified algorithm and password. Password based algorithms are taken from
 * providers registered to {@link Security}.
 * 
 * @author Nils Woehler
 * 
 */
public abstract class AbstractDocumentEncryptorOperator extends Operator {

	public static final String PARAMETER_FILE_INPUT = "document_input";
	public static final String PARAMETER_FILE_OUTPUT = "document_output";

	/**
	 * Used to test if encryption works with the current parameters.
	 */
	private static final String RANDOM_TEXT = "This is sparta!";

	private static final EncryptionAlgorithmProvider ALGORITHM_PROVIDER = new EncryptionAlgorithmProvider();

	public AbstractDocumentEncryptorOperator(OperatorDescription description) {
		super(description);

		getTransformer().addRule(new MDTransformationRule() {

			@Override
			public void transformMD() {
				try {
					transformText(configureEncryptor(), RANDOM_TEXT);
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

		// FIXME

	}

	/**
	 * Creates and configures a string encryptor.
	 */
	protected StandardPBEStringEncryptor configureEncryptor()
			throws UndefinedParameterError {
		return ALGORITHM_PROVIDER.configureStringEncryptor(this);
	}

	/**
	 * Transforms the input, e.g. encrypts or decrypts it with the provided
	 * {@link StandardPBEStringEncryptor}.
	 * 
	 * @param encryptor
	 *            the encryptor being used
	 * @param text
	 *            the text being encrypted/decrypted
	 * @return the encrypted/decrypted content
	 */
	protected abstract String transformText(
			StandardPBEStringEncryptor encryptor, String text) throws UserError;

	@Override
	public List<ParameterType> getParameterTypes() {
		List<ParameterType> parameterTypes = super.getParameterTypes();
		parameterTypes.addAll(ALGORITHM_PROVIDER.getParameterTypes());
		return parameterTypes;
	}
}
