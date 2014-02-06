package com.rapidminer.operator.nio.file;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.UserError;

/**
 * Decrypts files.
 * 
 * @author Nils Woehler
 * 
 */
public class DecryptFileOperator extends AbstractFileEncryptorOperator {

	public DecryptFileOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected byte[] transformFile(StandardPBEByteEncryptor encryptor,
			byte[] fileContent) throws UserError {
		try {
			return encryptor.decrypt(fileContent);
		} catch (EncryptionOperationNotPossibleException e) {
			throw new UserError(this, "file_decryption_failed"); 
			//TODO add error message asken the user to check password and algorithm
		}
	}

}