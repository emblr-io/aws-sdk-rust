// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Identifies which finding to get the finding history for.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsSecurityFindingIdentifier {
    /// <p>The identifier of the finding that was specified by the finding provider.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration.</p>
    pub product_arn: ::std::option::Option<::std::string::String>,
}
impl AwsSecurityFindingIdentifier {
    /// <p>The identifier of the finding that was specified by the finding provider.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration.</p>
    pub fn product_arn(&self) -> ::std::option::Option<&str> {
        self.product_arn.as_deref()
    }
}
impl AwsSecurityFindingIdentifier {
    /// Creates a new builder-style object to manufacture [`AwsSecurityFindingIdentifier`](crate::types::AwsSecurityFindingIdentifier).
    pub fn builder() -> crate::types::builders::AwsSecurityFindingIdentifierBuilder {
        crate::types::builders::AwsSecurityFindingIdentifierBuilder::default()
    }
}

/// A builder for [`AwsSecurityFindingIdentifier`](crate::types::AwsSecurityFindingIdentifier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsSecurityFindingIdentifierBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) product_arn: ::std::option::Option<::std::string::String>,
}
impl AwsSecurityFindingIdentifierBuilder {
    /// <p>The identifier of the finding that was specified by the finding provider.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the finding that was specified by the finding provider.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the finding that was specified by the finding provider.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration.</p>
    /// This field is required.
    pub fn product_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration.</p>
    pub fn set_product_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_arn = input;
        self
    }
    /// <p>The ARN generated by Security Hub that uniquely identifies a product that generates findings. This can be the ARN for a third-party product that is integrated with Security Hub, or the ARN for a custom integration.</p>
    pub fn get_product_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_arn
    }
    /// Consumes the builder and constructs a [`AwsSecurityFindingIdentifier`](crate::types::AwsSecurityFindingIdentifier).
    pub fn build(self) -> crate::types::AwsSecurityFindingIdentifier {
        crate::types::AwsSecurityFindingIdentifier {
            id: self.id,
            product_arn: self.product_arn,
        }
    }
}
