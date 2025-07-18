// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeGameSessionPlacementInput {
    /// <p>A unique identifier for a game session placement to retrieve.</p>
    pub placement_id: ::std::option::Option<::std::string::String>,
}
impl DescribeGameSessionPlacementInput {
    /// <p>A unique identifier for a game session placement to retrieve.</p>
    pub fn placement_id(&self) -> ::std::option::Option<&str> {
        self.placement_id.as_deref()
    }
}
impl DescribeGameSessionPlacementInput {
    /// Creates a new builder-style object to manufacture [`DescribeGameSessionPlacementInput`](crate::operation::describe_game_session_placement::DescribeGameSessionPlacementInput).
    pub fn builder() -> crate::operation::describe_game_session_placement::builders::DescribeGameSessionPlacementInputBuilder {
        crate::operation::describe_game_session_placement::builders::DescribeGameSessionPlacementInputBuilder::default()
    }
}

/// A builder for [`DescribeGameSessionPlacementInput`](crate::operation::describe_game_session_placement::DescribeGameSessionPlacementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeGameSessionPlacementInputBuilder {
    pub(crate) placement_id: ::std::option::Option<::std::string::String>,
}
impl DescribeGameSessionPlacementInputBuilder {
    /// <p>A unique identifier for a game session placement to retrieve.</p>
    /// This field is required.
    pub fn placement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.placement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for a game session placement to retrieve.</p>
    pub fn set_placement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.placement_id = input;
        self
    }
    /// <p>A unique identifier for a game session placement to retrieve.</p>
    pub fn get_placement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.placement_id
    }
    /// Consumes the builder and constructs a [`DescribeGameSessionPlacementInput`](crate::operation::describe_game_session_placement::DescribeGameSessionPlacementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_game_session_placement::DescribeGameSessionPlacementInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_game_session_placement::DescribeGameSessionPlacementInput {
            placement_id: self.placement_id,
        })
    }
}
