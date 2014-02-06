package com.rapidminer.operator.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.UserError;

/**
 * Decrypts text.
 * 
 * @author Nils Woehler
 * 
 */
public class DecryptDocumentOperator extends AbstractDocumentEncryptorOperator {

	public DecryptDocumentOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected String transformText(StandardPBEStringEncryptor encryptor,
			String text) throws UserError {
		try {
			return encryptor.decrypt(text);
		} catch (EncryptionOperationNotPossibleException e) {
			throw new UserError(this, "text_decryption_failed"); 
			//TODO add error message asken the user to check password and algorithm
		}
	}

}