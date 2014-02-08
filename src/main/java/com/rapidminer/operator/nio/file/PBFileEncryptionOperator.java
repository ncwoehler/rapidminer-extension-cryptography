/*
 *  RapidMiner Encryption Extension
 *
 *  Copyright (C) 2014 by Nils Wöhler
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

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import com.rapidminer.operator.OperatorDescription;
import com.rapidminer.operator.UserError;

/**
 * Operator for encrypting files.
 * 
 * @author Nils Woehler
 * 
 */
public class PBFileEncryptionOperator extends AbstractPBFileEncryptionOperator {

	public PBFileEncryptionOperator(OperatorDescription description) {
		super(description);
	}

	@Override
	protected byte[] transformFile(StandardPBEByteEncryptor encryptor,
			byte[] fileContent) throws UserError {
		try {
			return encryptor.encrypt(fileContent);
		} catch(EncryptionOperationNotPossibleException e){
			throw new UserError(this, e, "file.encryption_not_possible");
		}
	}

}
