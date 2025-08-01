// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDomainLayoutInput {
    /// <p>The unique name of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique name of the layout.</p>
    pub layout_definition_name: ::std::option::Option<::std::string::String>,
}
impl GetDomainLayoutInput {
    /// <p>The unique name of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The unique name of the layout.</p>
    pub fn layout_definition_name(&self) -> ::std::option::Option<&str> {
        self.layout_definition_name.as_deref()
    }
}
impl GetDomainLayoutInput {
    /// Creates a new builder-style object to manufacture [`GetDomainLayoutInput`](crate::operation::get_domain_layout::GetDomainLayoutInput).
    pub fn builder() -> crate::operation::get_domain_layout::builders::GetDomainLayoutInputBuilder {
        crate::operation::get_domain_layout::builders::GetDomainLayoutInputBuilder::default()
    }
}

/// A builder for [`GetDomainLayoutInput`](crate::operation::get_domain_layout::GetDomainLayoutInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDomainLayoutInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) layout_definition_name: ::std::option::Option<::std::string::String>,
}
impl GetDomainLayoutInputBuilder {
    /// <p>The unique name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The unique name of the layout.</p>
    /// This field is required.
    pub fn layout_definition_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.layout_definition_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the layout.</p>
    pub fn set_layout_definition_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.layout_definition_name = input;
        self
    }
    /// <p>The unique name of the layout.</p>
    pub fn get_layout_definition_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.layout_definition_name
    }
    /// Consumes the builder and constructs a [`GetDomainLayoutInput`](crate::operation::get_domain_layout::GetDomainLayoutInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_domain_layout::GetDomainLayoutInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_domain_layout::GetDomainLayoutInput {
            domain_name: self.domain_name,
            layout_definition_name: self.layout_definition_name,
        })
    }
}
