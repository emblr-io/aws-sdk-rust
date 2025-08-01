// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateDistributionWebAclInput {
    /// <p>The ID of the distribution.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the WAF web ACL to associate.</p>
    pub web_acl_arn: ::std::option::Option<::std::string::String>,
    /// <p>The value of the <code>ETag</code> header that you received when retrieving the distribution that you're associating with the WAF web ACL.</p>
    pub if_match: ::std::option::Option<::std::string::String>,
}
impl AssociateDistributionWebAclInput {
    /// <p>The ID of the distribution.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the WAF web ACL to associate.</p>
    pub fn web_acl_arn(&self) -> ::std::option::Option<&str> {
        self.web_acl_arn.as_deref()
    }
    /// <p>The value of the <code>ETag</code> header that you received when retrieving the distribution that you're associating with the WAF web ACL.</p>
    pub fn if_match(&self) -> ::std::option::Option<&str> {
        self.if_match.as_deref()
    }
}
impl AssociateDistributionWebAclInput {
    /// Creates a new builder-style object to manufacture [`AssociateDistributionWebAclInput`](crate::operation::associate_distribution_web_acl::AssociateDistributionWebAclInput).
    pub fn builder() -> crate::operation::associate_distribution_web_acl::builders::AssociateDistributionWebAclInputBuilder {
        crate::operation::associate_distribution_web_acl::builders::AssociateDistributionWebAclInputBuilder::default()
    }
}

/// A builder for [`AssociateDistributionWebAclInput`](crate::operation::associate_distribution_web_acl::AssociateDistributionWebAclInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateDistributionWebAclInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) web_acl_arn: ::std::option::Option<::std::string::String>,
    pub(crate) if_match: ::std::option::Option<::std::string::String>,
}
impl AssociateDistributionWebAclInputBuilder {
    /// <p>The ID of the distribution.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the distribution.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the distribution.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon Resource Name (ARN) of the WAF web ACL to associate.</p>
    /// This field is required.
    pub fn web_acl_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.web_acl_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the WAF web ACL to associate.</p>
    pub fn set_web_acl_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.web_acl_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the WAF web ACL to associate.</p>
    pub fn get_web_acl_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.web_acl_arn
    }
    /// <p>The value of the <code>ETag</code> header that you received when retrieving the distribution that you're associating with the WAF web ACL.</p>
    pub fn if_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the <code>ETag</code> header that you received when retrieving the distribution that you're associating with the WAF web ACL.</p>
    pub fn set_if_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_match = input;
        self
    }
    /// <p>The value of the <code>ETag</code> header that you received when retrieving the distribution that you're associating with the WAF web ACL.</p>
    pub fn get_if_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_match
    }
    /// Consumes the builder and constructs a [`AssociateDistributionWebAclInput`](crate::operation::associate_distribution_web_acl::AssociateDistributionWebAclInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_distribution_web_acl::AssociateDistributionWebAclInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::associate_distribution_web_acl::AssociateDistributionWebAclInput {
            id: self.id,
            web_acl_arn: self.web_acl_arn,
            if_match: self.if_match,
        })
    }
}
