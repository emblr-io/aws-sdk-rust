// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the source of a logical table. This is a variant type structure. For this structure to be valid, only one of the attributes can be non-null.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogicalTableSource {
    /// <p>Specifies the result of a join of two logical tables.</p>
    pub join_instruction: ::std::option::Option<crate::types::JoinInstruction>,
    /// <p>Physical table ID.</p>
    pub physical_table_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Number (ARN) of the parent dataset.</p>
    pub data_set_arn: ::std::option::Option<::std::string::String>,
}
impl LogicalTableSource {
    /// <p>Specifies the result of a join of two logical tables.</p>
    pub fn join_instruction(&self) -> ::std::option::Option<&crate::types::JoinInstruction> {
        self.join_instruction.as_ref()
    }
    /// <p>Physical table ID.</p>
    pub fn physical_table_id(&self) -> ::std::option::Option<&str> {
        self.physical_table_id.as_deref()
    }
    /// <p>The Amazon Resource Number (ARN) of the parent dataset.</p>
    pub fn data_set_arn(&self) -> ::std::option::Option<&str> {
        self.data_set_arn.as_deref()
    }
}
impl LogicalTableSource {
    /// Creates a new builder-style object to manufacture [`LogicalTableSource`](crate::types::LogicalTableSource).
    pub fn builder() -> crate::types::builders::LogicalTableSourceBuilder {
        crate::types::builders::LogicalTableSourceBuilder::default()
    }
}

/// A builder for [`LogicalTableSource`](crate::types::LogicalTableSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogicalTableSourceBuilder {
    pub(crate) join_instruction: ::std::option::Option<crate::types::JoinInstruction>,
    pub(crate) physical_table_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_set_arn: ::std::option::Option<::std::string::String>,
}
impl LogicalTableSourceBuilder {
    /// <p>Specifies the result of a join of two logical tables.</p>
    pub fn join_instruction(mut self, input: crate::types::JoinInstruction) -> Self {
        self.join_instruction = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the result of a join of two logical tables.</p>
    pub fn set_join_instruction(mut self, input: ::std::option::Option<crate::types::JoinInstruction>) -> Self {
        self.join_instruction = input;
        self
    }
    /// <p>Specifies the result of a join of two logical tables.</p>
    pub fn get_join_instruction(&self) -> &::std::option::Option<crate::types::JoinInstruction> {
        &self.join_instruction
    }
    /// <p>Physical table ID.</p>
    pub fn physical_table_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.physical_table_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Physical table ID.</p>
    pub fn set_physical_table_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.physical_table_id = input;
        self
    }
    /// <p>Physical table ID.</p>
    pub fn get_physical_table_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.physical_table_id
    }
    /// <p>The Amazon Resource Number (ARN) of the parent dataset.</p>
    pub fn data_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the parent dataset.</p>
    pub fn set_data_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_arn = input;
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the parent dataset.</p>
    pub fn get_data_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_arn
    }
    /// Consumes the builder and constructs a [`LogicalTableSource`](crate::types::LogicalTableSource).
    pub fn build(self) -> crate::types::LogicalTableSource {
        crate::types::LogicalTableSource {
            join_instruction: self.join_instruction,
            physical_table_id: self.physical_table_id,
            data_set_arn: self.data_set_arn,
        }
    }
}
