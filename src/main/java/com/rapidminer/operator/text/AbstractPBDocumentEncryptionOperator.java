package com.rapidminer.operator.text;

import java.security.Security;
import java.util.List;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import com.rapidminer.operator.PBEAlgorithmParameterHandler;
import com.rapidminer.operator.Operator;
import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.OperatorException;
import com.rapidminer.operator.ProcessSetupError.Severity;
import com.rapidminer.operator.SimpleProcessSetupError;
import com.rapidminer.operator.UserError;
import com.rapidminer.operator.ports.InputPort;
import com.rapidminer.operator.ports.OutputPort;
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
public abstract class AbstractPBDocumentEncryptionOperator extends Operator {

	public static final String DOCUMENT_INPUT = "document_input";
	public static final String DOCUMENT_OUTPUT = "document_output";

	/**
	 * Used to test if encryption works with the current parameters.
	 */
	private static final String RANDOM_TEXT = "This is sparta!";

	private static final PBEAlgorithmParameterHandler ALGORITHM_PROVIDER = new PBEAlgorithmParameterHandler();

	private final InputPort documentInput = getInputPorts().createPort(
			DOCUMENT_INPUT, Document.class);
	private final OutputPort documentOut = getOutputPorts().createPort(
			DOCUMENT_OUTPUT);

	public AbstractPBDocumentEncryptionOperator(OperatorDescription description) {
		super(description);

		getTransformer().addRule(new MDTransformationRule() {

			@Override
			public void transformMD() {
				try {
					StandardPBEStringEncryptor encryptor = configureEncryptor();
					encryptor.decrypt(encryptor.encrypt(RANDOM_TEXT));
				} catch (Throwable t) {
					addError(new SimpleProcessSetupError(Severity.ERROR,
							getPortOwner(), "text_encryption_error", t
									.getLocalizedMessage()));
				}
			}

		});
		getTransformer().addPassThroughRule(documentInput, documentOut);
	}

	@Override
	public void doWork() throws OperatorException {

		// retrieve document
		Document input = documentInput.getData(Document.class);

		// encrypt/decrypt text
		String text = transformText(configureEncryptor(), input.getText());

		// deliver transformed document
		documentOut.deliver(new Document(text));
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
		parameterTypes.addAll(ALGORITHM_PROVIDER.getParameterTypes(this));
		return parameterTypes;
	}
}
