// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration for uploading output data to Amazon S3 from the processing container.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProcessingS3Output {
    /// <p>A URI that identifies the Amazon S3 bucket where you want Amazon SageMaker to save the results of a processing job.</p>
    pub s3_uri: ::std::option::Option<::std::string::String>,
    /// <p>The local path of a directory where you want Amazon SageMaker to upload its contents to Amazon S3. <code>LocalPath</code> is an absolute path to a directory containing output files. This directory will be created by the platform and exist when your container's entrypoint is invoked.</p>
    pub local_path: ::std::option::Option<::std::string::String>,
    /// <p>Whether to upload the results of the processing job continuously or after the job completes.</p>
    pub s3_upload_mode: ::std::option::Option<crate::types::ProcessingS3UploadMode>,
}
impl ProcessingS3Output {
    /// <p>A URI that identifies the Amazon S3 bucket where you want Amazon SageMaker to save the results of a processing job.</p>
    pub fn s3_uri(&self) -> ::std::option::Option<&str> {
        self.s3_uri.as_deref()
    }
    /// <p>The local path of a directory where you want Amazon SageMaker to upload its contents to Amazon S3. <code>LocalPath</code> is an absolute path to a directory containing output files. This directory will be created by the platform and exist when your container's entrypoint is invoked.</p>
    pub fn local_path(&self) -> ::std::option::Option<&str> {
        self.local_path.as_deref()
    }
    /// <p>Whether to upload the results of the processing job continuously or after the job completes.</p>
    pub fn s3_upload_mode(&self) -> ::std::option::Option<&crate::types::ProcessingS3UploadMode> {
        self.s3_upload_mode.as_ref()
    }
}
impl ProcessingS3Output {
    /// Creates a new builder-style object to manufacture [`ProcessingS3Output`](crate::types::ProcessingS3Output).
    pub fn builder() -> crate::types::builders::ProcessingS3OutputBuilder {
        crate::types::builders::ProcessingS3OutputBuilder::default()
    }
}

/// A builder for [`ProcessingS3Output`](crate::types::ProcessingS3Output).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProcessingS3OutputBuilder {
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) local_path: ::std::option::Option<::std::string::String>,
    pub(crate) s3_upload_mode: ::std::option::Option<crate::types::ProcessingS3UploadMode>,
}
impl ProcessingS3OutputBuilder {
    /// <p>A URI that identifies the Amazon S3 bucket where you want Amazon SageMaker to save the results of a processing job.</p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A URI that identifies the Amazon S3 bucket where you want Amazon SageMaker to save the results of a processing job.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>A URI that identifies the Amazon S3 bucket where you want Amazon SageMaker to save the results of a processing job.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// <p>The local path of a directory where you want Amazon SageMaker to upload its contents to Amazon S3. <code>LocalPath</code> is an absolute path to a directory containing output files. This directory will be created by the platform and exist when your container's entrypoint is invoked.</p>
    pub fn local_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.local_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The local path of a directory where you want Amazon SageMaker to upload its contents to Amazon S3. <code>LocalPath</code> is an absolute path to a directory containing output files. This directory will be created by the platform and exist when your container's entrypoint is invoked.</p>
    pub fn set_local_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.local_path = input;
        self
    }
    /// <p>The local path of a directory where you want Amazon SageMaker to upload its contents to Amazon S3. <code>LocalPath</code> is an absolute path to a directory containing output files. This directory will be created by the platform and exist when your container's entrypoint is invoked.</p>
    pub fn get_local_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.local_path
    }
    /// <p>Whether to upload the results of the processing job continuously or after the job completes.</p>
    /// This field is required.
    pub fn s3_upload_mode(mut self, input: crate::types::ProcessingS3UploadMode) -> Self {
        self.s3_upload_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to upload the results of the processing job continuously or after the job completes.</p>
    pub fn set_s3_upload_mode(mut self, input: ::std::option::Option<crate::types::ProcessingS3UploadMode>) -> Self {
        self.s3_upload_mode = input;
        self
    }
    /// <p>Whether to upload the results of the processing job continuously or after the job completes.</p>
    pub fn get_s3_upload_mode(&self) -> &::std::option::Option<crate::types::ProcessingS3UploadMode> {
        &self.s3_upload_mode
    }
    /// Consumes the builder and constructs a [`ProcessingS3Output`](crate::types::ProcessingS3Output).
    pub fn build(self) -> crate::types::ProcessingS3Output {
        crate::types::ProcessingS3Output {
            s3_uri: self.s3_uri,
            local_path: self.local_path,
            s3_upload_mode: self.s3_upload_mode,
        }
    }
}
