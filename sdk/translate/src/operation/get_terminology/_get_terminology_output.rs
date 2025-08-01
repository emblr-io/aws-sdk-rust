// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTerminologyOutput {
    /// <p>The properties of the custom terminology being retrieved.</p>
    pub terminology_properties: ::std::option::Option<crate::types::TerminologyProperties>,
    /// <p>The Amazon S3 location of the most recent custom terminology input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub terminology_data_location: ::std::option::Option<crate::types::TerminologyDataLocation>,
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a terminology resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub auxiliary_data_location: ::std::option::Option<crate::types::TerminologyDataLocation>,
    _request_id: Option<String>,
}
impl GetTerminologyOutput {
    /// <p>The properties of the custom terminology being retrieved.</p>
    pub fn terminology_properties(&self) -> ::std::option::Option<&crate::types::TerminologyProperties> {
        self.terminology_properties.as_ref()
    }
    /// <p>The Amazon S3 location of the most recent custom terminology input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn terminology_data_location(&self) -> ::std::option::Option<&crate::types::TerminologyDataLocation> {
        self.terminology_data_location.as_ref()
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a terminology resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn auxiliary_data_location(&self) -> ::std::option::Option<&crate::types::TerminologyDataLocation> {
        self.auxiliary_data_location.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetTerminologyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTerminologyOutput {
    /// Creates a new builder-style object to manufacture [`GetTerminologyOutput`](crate::operation::get_terminology::GetTerminologyOutput).
    pub fn builder() -> crate::operation::get_terminology::builders::GetTerminologyOutputBuilder {
        crate::operation::get_terminology::builders::GetTerminologyOutputBuilder::default()
    }
}

/// A builder for [`GetTerminologyOutput`](crate::operation::get_terminology::GetTerminologyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTerminologyOutputBuilder {
    pub(crate) terminology_properties: ::std::option::Option<crate::types::TerminologyProperties>,
    pub(crate) terminology_data_location: ::std::option::Option<crate::types::TerminologyDataLocation>,
    pub(crate) auxiliary_data_location: ::std::option::Option<crate::types::TerminologyDataLocation>,
    _request_id: Option<String>,
}
impl GetTerminologyOutputBuilder {
    /// <p>The properties of the custom terminology being retrieved.</p>
    pub fn terminology_properties(mut self, input: crate::types::TerminologyProperties) -> Self {
        self.terminology_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties of the custom terminology being retrieved.</p>
    pub fn set_terminology_properties(mut self, input: ::std::option::Option<crate::types::TerminologyProperties>) -> Self {
        self.terminology_properties = input;
        self
    }
    /// <p>The properties of the custom terminology being retrieved.</p>
    pub fn get_terminology_properties(&self) -> &::std::option::Option<crate::types::TerminologyProperties> {
        &self.terminology_properties
    }
    /// <p>The Amazon S3 location of the most recent custom terminology input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn terminology_data_location(mut self, input: crate::types::TerminologyDataLocation) -> Self {
        self.terminology_data_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 location of the most recent custom terminology input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn set_terminology_data_location(mut self, input: ::std::option::Option<crate::types::TerminologyDataLocation>) -> Self {
        self.terminology_data_location = input;
        self
    }
    /// <p>The Amazon S3 location of the most recent custom terminology input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn get_terminology_data_location(&self) -> &::std::option::Option<crate::types::TerminologyDataLocation> {
        &self.terminology_data_location
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a terminology resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn auxiliary_data_location(mut self, input: crate::types::TerminologyDataLocation) -> Self {
        self.auxiliary_data_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a terminology resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn set_auxiliary_data_location(mut self, input: ::std::option::Option<crate::types::TerminologyDataLocation>) -> Self {
        self.auxiliary_data_location = input;
        self
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a terminology resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn get_auxiliary_data_location(&self) -> &::std::option::Option<crate::types::TerminologyDataLocation> {
        &self.auxiliary_data_location
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTerminologyOutput`](crate::operation::get_terminology::GetTerminologyOutput).
    pub fn build(self) -> crate::operation::get_terminology::GetTerminologyOutput {
        crate::operation::get_terminology::GetTerminologyOutput {
            terminology_properties: self.terminology_properties,
            terminology_data_location: self.terminology_data_location,
            auxiliary_data_location: self.auxiliary_data_location,
            _request_id: self._request_id,
        }
    }
}
