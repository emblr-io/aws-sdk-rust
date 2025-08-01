// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Each step type has its own <code>StepDetails</code> structure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DecryptStepDetails {
    /// <p>The name of the step, used as an identifier.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of encryption used. Currently, this value must be <code>PGP</code>.</p>
    pub r#type: crate::types::EncryptionType,
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub source_file_location: ::std::option::Option<::std::string::String>,
    /// <p>A flag that indicates whether to overwrite an existing file of the same name. The default is <code>FALSE</code>.</p>
    /// <p>If the workflow is processing a file that has the same name as an existing file, the behavior is as follows:</p>
    /// <ul>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>TRUE</code>, the existing file is replaced with the file being processed.</p></li>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>FALSE</code>, nothing happens, and the workflow processing stops.</p></li>
    /// </ul>
    pub overwrite_existing: ::std::option::Option<crate::types::OverwriteExisting>,
    /// <p>Specifies the location for the file being decrypted. Use <code>${Transfer:UserName}</code> or <code>${Transfer:UploadDate}</code> in this field to parametrize the destination prefix by username or uploaded date.</p>
    /// <ul>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UserName}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the name of the Transfer Family user that uploaded the file.</p></li>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UploadDate}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the date of the upload.</p><note>
    /// <p>The system resolves <code>UploadDate</code> to a date format of <i>YYYY-MM-DD</i>, based on the date the file is uploaded in UTC.</p>
    /// </note></li>
    /// </ul>
    pub destination_file_location: ::std::option::Option<crate::types::InputFileLocation>,
}
impl DecryptStepDetails {
    /// <p>The name of the step, used as an identifier.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of encryption used. Currently, this value must be <code>PGP</code>.</p>
    pub fn r#type(&self) -> &crate::types::EncryptionType {
        &self.r#type
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn source_file_location(&self) -> ::std::option::Option<&str> {
        self.source_file_location.as_deref()
    }
    /// <p>A flag that indicates whether to overwrite an existing file of the same name. The default is <code>FALSE</code>.</p>
    /// <p>If the workflow is processing a file that has the same name as an existing file, the behavior is as follows:</p>
    /// <ul>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>TRUE</code>, the existing file is replaced with the file being processed.</p></li>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>FALSE</code>, nothing happens, and the workflow processing stops.</p></li>
    /// </ul>
    pub fn overwrite_existing(&self) -> ::std::option::Option<&crate::types::OverwriteExisting> {
        self.overwrite_existing.as_ref()
    }
    /// <p>Specifies the location for the file being decrypted. Use <code>${Transfer:UserName}</code> or <code>${Transfer:UploadDate}</code> in this field to parametrize the destination prefix by username or uploaded date.</p>
    /// <ul>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UserName}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the name of the Transfer Family user that uploaded the file.</p></li>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UploadDate}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the date of the upload.</p><note>
    /// <p>The system resolves <code>UploadDate</code> to a date format of <i>YYYY-MM-DD</i>, based on the date the file is uploaded in UTC.</p>
    /// </note></li>
    /// </ul>
    pub fn destination_file_location(&self) -> ::std::option::Option<&crate::types::InputFileLocation> {
        self.destination_file_location.as_ref()
    }
}
impl DecryptStepDetails {
    /// Creates a new builder-style object to manufacture [`DecryptStepDetails`](crate::types::DecryptStepDetails).
    pub fn builder() -> crate::types::builders::DecryptStepDetailsBuilder {
        crate::types::builders::DecryptStepDetailsBuilder::default()
    }
}

/// A builder for [`DecryptStepDetails`](crate::types::DecryptStepDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DecryptStepDetailsBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::EncryptionType>,
    pub(crate) source_file_location: ::std::option::Option<::std::string::String>,
    pub(crate) overwrite_existing: ::std::option::Option<crate::types::OverwriteExisting>,
    pub(crate) destination_file_location: ::std::option::Option<crate::types::InputFileLocation>,
}
impl DecryptStepDetailsBuilder {
    /// <p>The name of the step, used as an identifier.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the step, used as an identifier.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the step, used as an identifier.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of encryption used. Currently, this value must be <code>PGP</code>.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::EncryptionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of encryption used. Currently, this value must be <code>PGP</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::EncryptionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of encryption used. Currently, this value must be <code>PGP</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::EncryptionType> {
        &self.r#type
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn source_file_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_file_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn set_source_file_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_file_location = input;
        self
    }
    /// <p>Specifies which file to use as input to the workflow step: either the output from the previous step, or the originally uploaded file for the workflow.</p>
    /// <ul>
    /// <li>
    /// <p>To use the previous file as the input, enter <code>${previous.file}</code>. In this case, this workflow step uses the output file from the previous workflow step as input. This is the default value.</p></li>
    /// <li>
    /// <p>To use the originally uploaded file location as input for this step, enter <code>${original.file}</code>.</p></li>
    /// </ul>
    pub fn get_source_file_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_file_location
    }
    /// <p>A flag that indicates whether to overwrite an existing file of the same name. The default is <code>FALSE</code>.</p>
    /// <p>If the workflow is processing a file that has the same name as an existing file, the behavior is as follows:</p>
    /// <ul>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>TRUE</code>, the existing file is replaced with the file being processed.</p></li>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>FALSE</code>, nothing happens, and the workflow processing stops.</p></li>
    /// </ul>
    pub fn overwrite_existing(mut self, input: crate::types::OverwriteExisting) -> Self {
        self.overwrite_existing = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag that indicates whether to overwrite an existing file of the same name. The default is <code>FALSE</code>.</p>
    /// <p>If the workflow is processing a file that has the same name as an existing file, the behavior is as follows:</p>
    /// <ul>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>TRUE</code>, the existing file is replaced with the file being processed.</p></li>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>FALSE</code>, nothing happens, and the workflow processing stops.</p></li>
    /// </ul>
    pub fn set_overwrite_existing(mut self, input: ::std::option::Option<crate::types::OverwriteExisting>) -> Self {
        self.overwrite_existing = input;
        self
    }
    /// <p>A flag that indicates whether to overwrite an existing file of the same name. The default is <code>FALSE</code>.</p>
    /// <p>If the workflow is processing a file that has the same name as an existing file, the behavior is as follows:</p>
    /// <ul>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>TRUE</code>, the existing file is replaced with the file being processed.</p></li>
    /// <li>
    /// <p>If <code>OverwriteExisting</code> is <code>FALSE</code>, nothing happens, and the workflow processing stops.</p></li>
    /// </ul>
    pub fn get_overwrite_existing(&self) -> &::std::option::Option<crate::types::OverwriteExisting> {
        &self.overwrite_existing
    }
    /// <p>Specifies the location for the file being decrypted. Use <code>${Transfer:UserName}</code> or <code>${Transfer:UploadDate}</code> in this field to parametrize the destination prefix by username or uploaded date.</p>
    /// <ul>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UserName}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the name of the Transfer Family user that uploaded the file.</p></li>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UploadDate}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the date of the upload.</p><note>
    /// <p>The system resolves <code>UploadDate</code> to a date format of <i>YYYY-MM-DD</i>, based on the date the file is uploaded in UTC.</p>
    /// </note></li>
    /// </ul>
    /// This field is required.
    pub fn destination_file_location(mut self, input: crate::types::InputFileLocation) -> Self {
        self.destination_file_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the location for the file being decrypted. Use <code>${Transfer:UserName}</code> or <code>${Transfer:UploadDate}</code> in this field to parametrize the destination prefix by username or uploaded date.</p>
    /// <ul>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UserName}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the name of the Transfer Family user that uploaded the file.</p></li>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UploadDate}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the date of the upload.</p><note>
    /// <p>The system resolves <code>UploadDate</code> to a date format of <i>YYYY-MM-DD</i>, based on the date the file is uploaded in UTC.</p>
    /// </note></li>
    /// </ul>
    pub fn set_destination_file_location(mut self, input: ::std::option::Option<crate::types::InputFileLocation>) -> Self {
        self.destination_file_location = input;
        self
    }
    /// <p>Specifies the location for the file being decrypted. Use <code>${Transfer:UserName}</code> or <code>${Transfer:UploadDate}</code> in this field to parametrize the destination prefix by username or uploaded date.</p>
    /// <ul>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UserName}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the name of the Transfer Family user that uploaded the file.</p></li>
    /// <li>
    /// <p>Set the value of <code>DestinationFileLocation</code> to <code>${Transfer:UploadDate}</code> to decrypt uploaded files to an Amazon S3 bucket that is prefixed with the date of the upload.</p><note>
    /// <p>The system resolves <code>UploadDate</code> to a date format of <i>YYYY-MM-DD</i>, based on the date the file is uploaded in UTC.</p>
    /// </note></li>
    /// </ul>
    pub fn get_destination_file_location(&self) -> &::std::option::Option<crate::types::InputFileLocation> {
        &self.destination_file_location
    }
    /// Consumes the builder and constructs a [`DecryptStepDetails`](crate::types::DecryptStepDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::DecryptStepDetailsBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::DecryptStepDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DecryptStepDetails {
            name: self.name,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building DecryptStepDetails",
                )
            })?,
            source_file_location: self.source_file_location,
            overwrite_existing: self.overwrite_existing,
            destination_file_location: self.destination_file_location,
        })
    }
}
