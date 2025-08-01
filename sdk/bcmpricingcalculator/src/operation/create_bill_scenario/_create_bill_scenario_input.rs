// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBillScenarioInput {
    /// <p>A descriptive name for the bill scenario.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The tags to apply to the bill scenario.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateBillScenarioInput {
    /// <p>A descriptive name for the bill scenario.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The tags to apply to the bill scenario.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateBillScenarioInput {
    /// Creates a new builder-style object to manufacture [`CreateBillScenarioInput`](crate::operation::create_bill_scenario::CreateBillScenarioInput).
    pub fn builder() -> crate::operation::create_bill_scenario::builders::CreateBillScenarioInputBuilder {
        crate::operation::create_bill_scenario::builders::CreateBillScenarioInputBuilder::default()
    }
}

/// A builder for [`CreateBillScenarioInput`](crate::operation::create_bill_scenario::CreateBillScenarioInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBillScenarioInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateBillScenarioInputBuilder {
    /// <p>A descriptive name for the bill scenario.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A descriptive name for the bill scenario.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A descriptive name for the bill scenario.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier to ensure idempotency of the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to apply to the bill scenario.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to apply to the bill scenario.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to apply to the bill scenario.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateBillScenarioInput`](crate::operation::create_bill_scenario::CreateBillScenarioInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_bill_scenario::CreateBillScenarioInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_bill_scenario::CreateBillScenarioInput {
            name: self.name,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
