// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetParallelDataOutput {
    /// <p>The properties of the parallel data resource that is being retrieved.</p>
    pub parallel_data_properties: ::std::option::Option<crate::types::ParallelDataProperties>,
    /// <p>The Amazon S3 location of the most recent parallel data input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub data_location: ::std::option::Option<crate::types::ParallelDataDataLocation>,
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub auxiliary_data_location: ::std::option::Option<crate::types::ParallelDataDataLocation>,
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to update a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub latest_update_attempt_auxiliary_data_location: ::std::option::Option<crate::types::ParallelDataDataLocation>,
    _request_id: Option<String>,
}
impl GetParallelDataOutput {
    /// <p>The properties of the parallel data resource that is being retrieved.</p>
    pub fn parallel_data_properties(&self) -> ::std::option::Option<&crate::types::ParallelDataProperties> {
        self.parallel_data_properties.as_ref()
    }
    /// <p>The Amazon S3 location of the most recent parallel data input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn data_location(&self) -> ::std::option::Option<&crate::types::ParallelDataDataLocation> {
        self.data_location.as_ref()
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn auxiliary_data_location(&self) -> ::std::option::Option<&crate::types::ParallelDataDataLocation> {
        self.auxiliary_data_location.as_ref()
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to update a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn latest_update_attempt_auxiliary_data_location(&self) -> ::std::option::Option<&crate::types::ParallelDataDataLocation> {
        self.latest_update_attempt_auxiliary_data_location.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetParallelDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetParallelDataOutput {
    /// Creates a new builder-style object to manufacture [`GetParallelDataOutput`](crate::operation::get_parallel_data::GetParallelDataOutput).
    pub fn builder() -> crate::operation::get_parallel_data::builders::GetParallelDataOutputBuilder {
        crate::operation::get_parallel_data::builders::GetParallelDataOutputBuilder::default()
    }
}

/// A builder for [`GetParallelDataOutput`](crate::operation::get_parallel_data::GetParallelDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetParallelDataOutputBuilder {
    pub(crate) parallel_data_properties: ::std::option::Option<crate::types::ParallelDataProperties>,
    pub(crate) data_location: ::std::option::Option<crate::types::ParallelDataDataLocation>,
    pub(crate) auxiliary_data_location: ::std::option::Option<crate::types::ParallelDataDataLocation>,
    pub(crate) latest_update_attempt_auxiliary_data_location: ::std::option::Option<crate::types::ParallelDataDataLocation>,
    _request_id: Option<String>,
}
impl GetParallelDataOutputBuilder {
    /// <p>The properties of the parallel data resource that is being retrieved.</p>
    pub fn parallel_data_properties(mut self, input: crate::types::ParallelDataProperties) -> Self {
        self.parallel_data_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties of the parallel data resource that is being retrieved.</p>
    pub fn set_parallel_data_properties(mut self, input: ::std::option::Option<crate::types::ParallelDataProperties>) -> Self {
        self.parallel_data_properties = input;
        self
    }
    /// <p>The properties of the parallel data resource that is being retrieved.</p>
    pub fn get_parallel_data_properties(&self) -> &::std::option::Option<crate::types::ParallelDataProperties> {
        &self.parallel_data_properties
    }
    /// <p>The Amazon S3 location of the most recent parallel data input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn data_location(mut self, input: crate::types::ParallelDataDataLocation) -> Self {
        self.data_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 location of the most recent parallel data input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn set_data_location(mut self, input: ::std::option::Option<crate::types::ParallelDataDataLocation>) -> Self {
        self.data_location = input;
        self
    }
    /// <p>The Amazon S3 location of the most recent parallel data input file that was successfully imported into Amazon Translate. The location is returned as a presigned URL that has a 30-minute expiration.</p><important>
    /// <p>Amazon Translate doesn't scan all input files for the risk of CSV injection attacks.</p>
    /// <p>CSV injection occurs when a .csv or .tsv file is altered so that a record contains malicious code. The record begins with a special character, such as =, +, -, or @. When the file is opened in a spreadsheet program, the program might interpret the record as a formula and run the code within it.</p>
    /// <p>Before you download an input file from Amazon S3, ensure that you recognize the file and trust its creator.</p>
    /// </important>
    pub fn get_data_location(&self) -> &::std::option::Option<crate::types::ParallelDataDataLocation> {
        &self.data_location
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn auxiliary_data_location(mut self, input: crate::types::ParallelDataDataLocation) -> Self {
        self.auxiliary_data_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn set_auxiliary_data_location(mut self, input: ::std::option::Option<crate::types::ParallelDataDataLocation>) -> Self {
        self.auxiliary_data_location = input;
        self
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to create a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn get_auxiliary_data_location(&self) -> &::std::option::Option<crate::types::ParallelDataDataLocation> {
        &self.auxiliary_data_location
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to update a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn latest_update_attempt_auxiliary_data_location(mut self, input: crate::types::ParallelDataDataLocation) -> Self {
        self.latest_update_attempt_auxiliary_data_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to update a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn set_latest_update_attempt_auxiliary_data_location(mut self, input: ::std::option::Option<crate::types::ParallelDataDataLocation>) -> Self {
        self.latest_update_attempt_auxiliary_data_location = input;
        self
    }
    /// <p>The Amazon S3 location of a file that provides any errors or warnings that were produced by your input file. This file was created when Amazon Translate attempted to update a parallel data resource. The location is returned as a presigned URL to that has a 30-minute expiration.</p>
    pub fn get_latest_update_attempt_auxiliary_data_location(&self) -> &::std::option::Option<crate::types::ParallelDataDataLocation> {
        &self.latest_update_attempt_auxiliary_data_location
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetParallelDataOutput`](crate::operation::get_parallel_data::GetParallelDataOutput).
    pub fn build(self) -> crate::operation::get_parallel_data::GetParallelDataOutput {
        crate::operation::get_parallel_data::GetParallelDataOutput {
            parallel_data_properties: self.parallel_data_properties,
            data_location: self.data_location,
            auxiliary_data_location: self.auxiliary_data_location,
            latest_update_attempt_auxiliary_data_location: self.latest_update_attempt_auxiliary_data_location,
            _request_id: self._request_id,
        }
    }
}
