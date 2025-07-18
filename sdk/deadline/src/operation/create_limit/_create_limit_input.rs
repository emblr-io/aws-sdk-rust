// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateLimitInput {
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The display name of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The value that you specify as the <code>name</code> in the <code>amounts</code> field of the <code>hostRequirements</code> in a step of a job template to declare the limit requirement.</p>
    pub amount_requirement_name: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of resources constrained by this limit. When all of the resources are in use, steps that require the limit won't be scheduled until the resource is available.</p>
    /// <p>The <code>maxCount</code> must not be 0. If the value is -1, there is no restriction on the number of resources that can be acquired for this limit.</p>
    pub max_count: ::std::option::Option<i32>,
    /// <p>The farm ID of the farm that contains the limit.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>A description of the limit. A description helps you identify the purpose of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub description: ::std::option::Option<::std::string::String>,
}
impl CreateLimitInput {
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The display name of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The value that you specify as the <code>name</code> in the <code>amounts</code> field of the <code>hostRequirements</code> in a step of a job template to declare the limit requirement.</p>
    pub fn amount_requirement_name(&self) -> ::std::option::Option<&str> {
        self.amount_requirement_name.as_deref()
    }
    /// <p>The maximum number of resources constrained by this limit. When all of the resources are in use, steps that require the limit won't be scheduled until the resource is available.</p>
    /// <p>The <code>maxCount</code> must not be 0. If the value is -1, there is no restriction on the number of resources that can be acquired for this limit.</p>
    pub fn max_count(&self) -> ::std::option::Option<i32> {
        self.max_count
    }
    /// <p>The farm ID of the farm that contains the limit.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>A description of the limit. A description helps you identify the purpose of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl ::std::fmt::Debug for CreateLimitInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateLimitInput");
        formatter.field("client_token", &self.client_token);
        formatter.field("display_name", &self.display_name);
        formatter.field("amount_requirement_name", &self.amount_requirement_name);
        formatter.field("max_count", &self.max_count);
        formatter.field("farm_id", &self.farm_id);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateLimitInput {
    /// Creates a new builder-style object to manufacture [`CreateLimitInput`](crate::operation::create_limit::CreateLimitInput).
    pub fn builder() -> crate::operation::create_limit::builders::CreateLimitInputBuilder {
        crate::operation::create_limit::builders::CreateLimitInputBuilder::default()
    }
}

/// A builder for [`CreateLimitInput`](crate::operation::create_limit::CreateLimitInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateLimitInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) amount_requirement_name: ::std::option::Option<::std::string::String>,
    pub(crate) max_count: ::std::option::Option<i32>,
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl CreateLimitInputBuilder {
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The unique token which the server uses to recognize retries of the same request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The display name of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    /// This field is required.
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The value that you specify as the <code>name</code> in the <code>amounts</code> field of the <code>hostRequirements</code> in a step of a job template to declare the limit requirement.</p>
    /// This field is required.
    pub fn amount_requirement_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.amount_requirement_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value that you specify as the <code>name</code> in the <code>amounts</code> field of the <code>hostRequirements</code> in a step of a job template to declare the limit requirement.</p>
    pub fn set_amount_requirement_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.amount_requirement_name = input;
        self
    }
    /// <p>The value that you specify as the <code>name</code> in the <code>amounts</code> field of the <code>hostRequirements</code> in a step of a job template to declare the limit requirement.</p>
    pub fn get_amount_requirement_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.amount_requirement_name
    }
    /// <p>The maximum number of resources constrained by this limit. When all of the resources are in use, steps that require the limit won't be scheduled until the resource is available.</p>
    /// <p>The <code>maxCount</code> must not be 0. If the value is -1, there is no restriction on the number of resources that can be acquired for this limit.</p>
    /// This field is required.
    pub fn max_count(mut self, input: i32) -> Self {
        self.max_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of resources constrained by this limit. When all of the resources are in use, steps that require the limit won't be scheduled until the resource is available.</p>
    /// <p>The <code>maxCount</code> must not be 0. If the value is -1, there is no restriction on the number of resources that can be acquired for this limit.</p>
    pub fn set_max_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_count = input;
        self
    }
    /// <p>The maximum number of resources constrained by this limit. When all of the resources are in use, steps that require the limit won't be scheduled until the resource is available.</p>
    /// <p>The <code>maxCount</code> must not be 0. If the value is -1, there is no restriction on the number of resources that can be acquired for this limit.</p>
    pub fn get_max_count(&self) -> &::std::option::Option<i32> {
        &self.max_count
    }
    /// <p>The farm ID of the farm that contains the limit.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The farm ID of the farm that contains the limit.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The farm ID of the farm that contains the limit.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>A description of the limit. A description helps you identify the purpose of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the limit. A description helps you identify the purpose of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the limit. A description helps you identify the purpose of the limit.</p><important>
    /// <p>This field can store any content. Escape or encode this content before displaying it on a webpage or any other system that might interpret the content of this field.</p>
    /// </important>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`CreateLimitInput`](crate::operation::create_limit::CreateLimitInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_limit::CreateLimitInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_limit::CreateLimitInput {
            client_token: self.client_token,
            display_name: self.display_name,
            amount_requirement_name: self.amount_requirement_name,
            max_count: self.max_count,
            farm_id: self.farm_id,
            description: self.description,
        })
    }
}
impl ::std::fmt::Debug for CreateLimitInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateLimitInputBuilder");
        formatter.field("client_token", &self.client_token);
        formatter.field("display_name", &self.display_name);
        formatter.field("amount_requirement_name", &self.amount_requirement_name);
        formatter.field("max_count", &self.max_count);
        formatter.field("farm_id", &self.farm_id);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
