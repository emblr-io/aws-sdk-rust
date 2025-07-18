// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon QuickSight configuration for an Amazon Q Business application that uses QuickSight as the identity provider. For more information, see <a href="https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/create-quicksight-integrated-application.html">Creating an Amazon QuickSight integrated application</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QuickSightConfiguration {
    /// <p>The Amazon QuickSight namespace that is used as the identity provider. For more information about QuickSight namespaces, see <a href="https://docs.aws.amazon.com/quicksight/latest/developerguide/namespace-operations.html">Namespace operations</a>.</p>
    pub client_namespace: ::std::string::String,
}
impl QuickSightConfiguration {
    /// <p>The Amazon QuickSight namespace that is used as the identity provider. For more information about QuickSight namespaces, see <a href="https://docs.aws.amazon.com/quicksight/latest/developerguide/namespace-operations.html">Namespace operations</a>.</p>
    pub fn client_namespace(&self) -> &str {
        use std::ops::Deref;
        self.client_namespace.deref()
    }
}
impl QuickSightConfiguration {
    /// Creates a new builder-style object to manufacture [`QuickSightConfiguration`](crate::types::QuickSightConfiguration).
    pub fn builder() -> crate::types::builders::QuickSightConfigurationBuilder {
        crate::types::builders::QuickSightConfigurationBuilder::default()
    }
}

/// A builder for [`QuickSightConfiguration`](crate::types::QuickSightConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QuickSightConfigurationBuilder {
    pub(crate) client_namespace: ::std::option::Option<::std::string::String>,
}
impl QuickSightConfigurationBuilder {
    /// <p>The Amazon QuickSight namespace that is used as the identity provider. For more information about QuickSight namespaces, see <a href="https://docs.aws.amazon.com/quicksight/latest/developerguide/namespace-operations.html">Namespace operations</a>.</p>
    /// This field is required.
    pub fn client_namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon QuickSight namespace that is used as the identity provider. For more information about QuickSight namespaces, see <a href="https://docs.aws.amazon.com/quicksight/latest/developerguide/namespace-operations.html">Namespace operations</a>.</p>
    pub fn set_client_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_namespace = input;
        self
    }
    /// <p>The Amazon QuickSight namespace that is used as the identity provider. For more information about QuickSight namespaces, see <a href="https://docs.aws.amazon.com/quicksight/latest/developerguide/namespace-operations.html">Namespace operations</a>.</p>
    pub fn get_client_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_namespace
    }
    /// Consumes the builder and constructs a [`QuickSightConfiguration`](crate::types::QuickSightConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`client_namespace`](crate::types::builders::QuickSightConfigurationBuilder::client_namespace)
    pub fn build(self) -> ::std::result::Result<crate::types::QuickSightConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::QuickSightConfiguration {
            client_namespace: self.client_namespace.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "client_namespace",
                    "client_namespace was not specified but it is required when building QuickSightConfiguration",
                )
            })?,
        })
    }
}
