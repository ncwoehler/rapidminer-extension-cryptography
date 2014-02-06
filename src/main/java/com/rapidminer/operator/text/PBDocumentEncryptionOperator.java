package com.rapidminer.operator.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.UserError;

/**
 * Encrypts files.
 * 
 * @author Nils Woehler
 * 
 */
public class PBDocumentEncryptionOperator extends AbstractPBDocumentEncryptionOperator {

	public PBDocumentEncryptionOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected String transformText(StandardPBEStringEncryptor encryptor,
			String text) throws UserError {
		return encryptor.encrypt(text);
	}

}
