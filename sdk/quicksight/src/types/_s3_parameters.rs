// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for S3.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3Parameters {
    /// <p>Location of the Amazon S3 manifest file. This is NULL if the manifest file was uploaded into Amazon QuickSight.</p>
    pub manifest_file_location: ::std::option::Option<crate::types::ManifestFileLocation>,
    /// <p>Use the <code>RoleArn</code> structure to override an account-wide role for a specific S3 data source. For example, say an account administrator has turned off all S3 access with an account-wide role. The administrator can then use <code>RoleArn</code> to bypass the account-wide role and allow S3 access for the single S3 data source that is specified in the structure, even if the account-wide role forbidding S3 access is still active.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
}
impl S3Parameters {
    /// <p>Location of the Amazon S3 manifest file. This is NULL if the manifest file was uploaded into Amazon QuickSight.</p>
    pub fn manifest_file_location(&self) -> ::std::option::Option<&crate::types::ManifestFileLocation> {
        self.manifest_file_location.as_ref()
    }
    /// <p>Use the <code>RoleArn</code> structure to override an account-wide role for a specific S3 data source. For example, say an account administrator has turned off all S3 access with an account-wide role. The administrator can then use <code>RoleArn</code> to bypass the account-wide role and allow S3 access for the single S3 data source that is specified in the structure, even if the account-wide role forbidding S3 access is still active.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
}
impl S3Parameters {
    /// Creates a new builder-style object to manufacture [`S3Parameters`](crate::types::S3Parameters).
    pub fn builder() -> crate::types::builders::S3ParametersBuilder {
        crate::types::builders::S3ParametersBuilder::default()
    }
}

/// A builder for [`S3Parameters`](crate::types::S3Parameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3ParametersBuilder {
    pub(crate) manifest_file_location: ::std::option::Option<crate::types::ManifestFileLocation>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl S3ParametersBuilder {
    /// <p>Location of the Amazon S3 manifest file. This is NULL if the manifest file was uploaded into Amazon QuickSight.</p>
    /// This field is required.
    pub fn manifest_file_location(mut self, input: crate::types::ManifestFileLocation) -> Self {
        self.manifest_file_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Location of the Amazon S3 manifest file. This is NULL if the manifest file was uploaded into Amazon QuickSight.</p>
    pub fn set_manifest_file_location(mut self, input: ::std::option::Option<crate::types::ManifestFileLocation>) -> Self {
        self.manifest_file_location = input;
        self
    }
    /// <p>Location of the Amazon S3 manifest file. This is NULL if the manifest file was uploaded into Amazon QuickSight.</p>
    pub fn get_manifest_file_location(&self) -> &::std::option::Option<crate::types::ManifestFileLocation> {
        &self.manifest_file_location
    }
    /// <p>Use the <code>RoleArn</code> structure to override an account-wide role for a specific S3 data source. For example, say an account administrator has turned off all S3 access with an account-wide role. The administrator can then use <code>RoleArn</code> to bypass the account-wide role and allow S3 access for the single S3 data source that is specified in the structure, even if the account-wide role forbidding S3 access is still active.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use the <code>RoleArn</code> structure to override an account-wide role for a specific S3 data source. For example, say an account administrator has turned off all S3 access with an account-wide role. The administrator can then use <code>RoleArn</code> to bypass the account-wide role and allow S3 access for the single S3 data source that is specified in the structure, even if the account-wide role forbidding S3 access is still active.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>Use the <code>RoleArn</code> structure to override an account-wide role for a specific S3 data source. For example, say an account administrator has turned off all S3 access with an account-wide role. The administrator can then use <code>RoleArn</code> to bypass the account-wide role and allow S3 access for the single S3 data source that is specified in the structure, even if the account-wide role forbidding S3 access is still active.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`S3Parameters`](crate::types::S3Parameters).
    pub fn build(self) -> crate::types::S3Parameters {
        crate::types::S3Parameters {
            manifest_file_location: self.manifest_file_location,
            role_arn: self.role_arn,
        }
    }
}
