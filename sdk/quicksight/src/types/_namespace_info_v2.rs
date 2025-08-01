// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The error type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NamespaceInfoV2 {
    /// <p>The name of the error.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The namespace ARN.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The namespace Amazon Web Services Region.</p>
    pub capacity_region: ::std::option::Option<::std::string::String>,
    /// <p>The creation status of a namespace that is not yet completely created.</p>
    pub creation_status: ::std::option::Option<crate::types::NamespaceStatus>,
    /// <p>The identity store used for the namespace.</p>
    pub identity_store: ::std::option::Option<crate::types::IdentityStore>,
    /// <p>An error that occurred when the namespace was created.</p>
    pub namespace_error: ::std::option::Option<crate::types::NamespaceError>,
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center application.</p>
    pub iam_identity_center_application_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center instance.</p>
    pub iam_identity_center_instance_arn: ::std::option::Option<::std::string::String>,
}
impl NamespaceInfoV2 {
    /// <p>The name of the error.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The namespace ARN.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The namespace Amazon Web Services Region.</p>
    pub fn capacity_region(&self) -> ::std::option::Option<&str> {
        self.capacity_region.as_deref()
    }
    /// <p>The creation status of a namespace that is not yet completely created.</p>
    pub fn creation_status(&self) -> ::std::option::Option<&crate::types::NamespaceStatus> {
        self.creation_status.as_ref()
    }
    /// <p>The identity store used for the namespace.</p>
    pub fn identity_store(&self) -> ::std::option::Option<&crate::types::IdentityStore> {
        self.identity_store.as_ref()
    }
    /// <p>An error that occurred when the namespace was created.</p>
    pub fn namespace_error(&self) -> ::std::option::Option<&crate::types::NamespaceError> {
        self.namespace_error.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center application.</p>
    pub fn iam_identity_center_application_arn(&self) -> ::std::option::Option<&str> {
        self.iam_identity_center_application_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center instance.</p>
    pub fn iam_identity_center_instance_arn(&self) -> ::std::option::Option<&str> {
        self.iam_identity_center_instance_arn.as_deref()
    }
}
impl NamespaceInfoV2 {
    /// Creates a new builder-style object to manufacture [`NamespaceInfoV2`](crate::types::NamespaceInfoV2).
    pub fn builder() -> crate::types::builders::NamespaceInfoV2Builder {
        crate::types::builders::NamespaceInfoV2Builder::default()
    }
}

/// A builder for [`NamespaceInfoV2`](crate::types::NamespaceInfoV2).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NamespaceInfoV2Builder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) capacity_region: ::std::option::Option<::std::string::String>,
    pub(crate) creation_status: ::std::option::Option<crate::types::NamespaceStatus>,
    pub(crate) identity_store: ::std::option::Option<crate::types::IdentityStore>,
    pub(crate) namespace_error: ::std::option::Option<crate::types::NamespaceError>,
    pub(crate) iam_identity_center_application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) iam_identity_center_instance_arn: ::std::option::Option<::std::string::String>,
}
impl NamespaceInfoV2Builder {
    /// <p>The name of the error.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the error.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the error.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The namespace ARN.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The namespace ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The namespace Amazon Web Services Region.</p>
    pub fn capacity_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.capacity_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace Amazon Web Services Region.</p>
    pub fn set_capacity_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.capacity_region = input;
        self
    }
    /// <p>The namespace Amazon Web Services Region.</p>
    pub fn get_capacity_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.capacity_region
    }
    /// <p>The creation status of a namespace that is not yet completely created.</p>
    pub fn creation_status(mut self, input: crate::types::NamespaceStatus) -> Self {
        self.creation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation status of a namespace that is not yet completely created.</p>
    pub fn set_creation_status(mut self, input: ::std::option::Option<crate::types::NamespaceStatus>) -> Self {
        self.creation_status = input;
        self
    }
    /// <p>The creation status of a namespace that is not yet completely created.</p>
    pub fn get_creation_status(&self) -> &::std::option::Option<crate::types::NamespaceStatus> {
        &self.creation_status
    }
    /// <p>The identity store used for the namespace.</p>
    pub fn identity_store(mut self, input: crate::types::IdentityStore) -> Self {
        self.identity_store = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identity store used for the namespace.</p>
    pub fn set_identity_store(mut self, input: ::std::option::Option<crate::types::IdentityStore>) -> Self {
        self.identity_store = input;
        self
    }
    /// <p>The identity store used for the namespace.</p>
    pub fn get_identity_store(&self) -> &::std::option::Option<crate::types::IdentityStore> {
        &self.identity_store
    }
    /// <p>An error that occurred when the namespace was created.</p>
    pub fn namespace_error(mut self, input: crate::types::NamespaceError) -> Self {
        self.namespace_error = ::std::option::Option::Some(input);
        self
    }
    /// <p>An error that occurred when the namespace was created.</p>
    pub fn set_namespace_error(mut self, input: ::std::option::Option<crate::types::NamespaceError>) -> Self {
        self.namespace_error = input;
        self
    }
    /// <p>An error that occurred when the namespace was created.</p>
    pub fn get_namespace_error(&self) -> &::std::option::Option<crate::types::NamespaceError> {
        &self.namespace_error
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center application.</p>
    pub fn iam_identity_center_application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_identity_center_application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center application.</p>
    pub fn set_iam_identity_center_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_identity_center_application_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center application.</p>
    pub fn get_iam_identity_center_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_identity_center_application_arn
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center instance.</p>
    pub fn iam_identity_center_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_identity_center_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center instance.</p>
    pub fn set_iam_identity_center_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_identity_center_instance_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the IAM Identity Center instance.</p>
    pub fn get_iam_identity_center_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_identity_center_instance_arn
    }
    /// Consumes the builder and constructs a [`NamespaceInfoV2`](crate::types::NamespaceInfoV2).
    pub fn build(self) -> crate::types::NamespaceInfoV2 {
        crate::types::NamespaceInfoV2 {
            name: self.name,
            arn: self.arn,
            capacity_region: self.capacity_region,
            creation_status: self.creation_status,
            identity_store: self.identity_store,
            namespace_error: self.namespace_error,
            iam_identity_center_application_arn: self.iam_identity_center_application_arn,
            iam_identity_center_instance_arn: self.iam_identity_center_instance_arn,
        }
    }
}
