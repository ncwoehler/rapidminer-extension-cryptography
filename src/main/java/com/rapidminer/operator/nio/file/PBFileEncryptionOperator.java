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

import com.rapidminer.operator.OperatorDescription;

/**
 * Encrypts files.
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
			byte[] fileContent) {
		return encryptor.encrypt(fileContent);
	}

}
