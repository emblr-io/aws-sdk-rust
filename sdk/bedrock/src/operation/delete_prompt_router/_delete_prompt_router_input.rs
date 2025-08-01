// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePromptRouterInput {
    /// <p>The Amazon Resource Name (ARN) of the prompt router to delete.</p>
    pub prompt_router_arn: ::std::option::Option<::std::string::String>,
}
impl DeletePromptRouterInput {
    /// <p>The Amazon Resource Name (ARN) of the prompt router to delete.</p>
    pub fn prompt_router_arn(&self) -> ::std::option::Option<&str> {
        self.prompt_router_arn.as_deref()
    }
}
impl DeletePromptRouterInput {
    /// Creates a new builder-style object to manufacture [`DeletePromptRouterInput`](crate::operation::delete_prompt_router::DeletePromptRouterInput).
    pub fn builder() -> crate::operation::delete_prompt_router::builders::DeletePromptRouterInputBuilder {
        crate::operation::delete_prompt_router::builders::DeletePromptRouterInputBuilder::default()
    }
}

/// A builder for [`DeletePromptRouterInput`](crate::operation::delete_prompt_router::DeletePromptRouterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePromptRouterInputBuilder {
    pub(crate) prompt_router_arn: ::std::option::Option<::std::string::String>,
}
impl DeletePromptRouterInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the prompt router to delete.</p>
    /// This field is required.
    pub fn prompt_router_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prompt_router_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the prompt router to delete.</p>
    pub fn set_prompt_router_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prompt_router_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the prompt router to delete.</p>
    pub fn get_prompt_router_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.prompt_router_arn
    }
    /// Consumes the builder and constructs a [`DeletePromptRouterInput`](crate::operation::delete_prompt_router::DeletePromptRouterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_prompt_router::DeletePromptRouterInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_prompt_router::DeletePromptRouterInput {
            prompt_router_arn: self.prompt_router_arn,
        })
    }
}
