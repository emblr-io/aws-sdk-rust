// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportStacksToStackSetInput {
    /// <p>The name of the stack set. The name must be unique in the Region where you create your stack set.</p>
    pub stack_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The IDs of the stacks you are importing into a stack set. You import up to 10 stacks per stack set at a time.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub stack_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon S3 URL which contains list of stack ids to be inputted.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub stack_ids_url: ::std::option::Option<::std::string::String>,
    /// <p>The list of OU ID's to which the stacks being imported has to be mapped as deployment target.</p>
    pub organizational_unit_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The user-specified preferences for how CloudFormation performs a stack set operation.</p>
    /// <p>For more information about maximum concurrent accounts and failure tolerance, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html#stackset-ops-options">Stack set operation options</a>.</p>
    pub operation_preferences: ::std::option::Option<crate::types::StackSetOperationPreferences>,
    /// <p>A unique, user defined, identifier for the stack set operation.</p>
    pub operation_id: ::std::option::Option<::std::string::String>,
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>For service managed stack sets, specify <code>DELEGATED_ADMIN</code>.</p></li>
    /// </ul>
    pub call_as: ::std::option::Option<crate::types::CallAs>,
}
impl ImportStacksToStackSetInput {
    /// <p>The name of the stack set. The name must be unique in the Region where you create your stack set.</p>
    pub fn stack_set_name(&self) -> ::std::option::Option<&str> {
        self.stack_set_name.as_deref()
    }
    /// <p>The IDs of the stacks you are importing into a stack set. You import up to 10 stacks per stack set at a time.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stack_ids.is_none()`.
    pub fn stack_ids(&self) -> &[::std::string::String] {
        self.stack_ids.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon S3 URL which contains list of stack ids to be inputted.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub fn stack_ids_url(&self) -> ::std::option::Option<&str> {
        self.stack_ids_url.as_deref()
    }
    /// <p>The list of OU ID's to which the stacks being imported has to be mapped as deployment target.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.organizational_unit_ids.is_none()`.
    pub fn organizational_unit_ids(&self) -> &[::std::string::String] {
        self.organizational_unit_ids.as_deref().unwrap_or_default()
    }
    /// <p>The user-specified preferences for how CloudFormation performs a stack set operation.</p>
    /// <p>For more information about maximum concurrent accounts and failure tolerance, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html#stackset-ops-options">Stack set operation options</a>.</p>
    pub fn operation_preferences(&self) -> ::std::option::Option<&crate::types::StackSetOperationPreferences> {
        self.operation_preferences.as_ref()
    }
    /// <p>A unique, user defined, identifier for the stack set operation.</p>
    pub fn operation_id(&self) -> ::std::option::Option<&str> {
        self.operation_id.as_deref()
    }
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>For service managed stack sets, specify <code>DELEGATED_ADMIN</code>.</p></li>
    /// </ul>
    pub fn call_as(&self) -> ::std::option::Option<&crate::types::CallAs> {
        self.call_as.as_ref()
    }
}
impl ImportStacksToStackSetInput {
    /// Creates a new builder-style object to manufacture [`ImportStacksToStackSetInput`](crate::operation::import_stacks_to_stack_set::ImportStacksToStackSetInput).
    pub fn builder() -> crate::operation::import_stacks_to_stack_set::builders::ImportStacksToStackSetInputBuilder {
        crate::operation::import_stacks_to_stack_set::builders::ImportStacksToStackSetInputBuilder::default()
    }
}

/// A builder for [`ImportStacksToStackSetInput`](crate::operation::import_stacks_to_stack_set::ImportStacksToStackSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportStacksToStackSetInputBuilder {
    pub(crate) stack_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) stack_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) stack_ids_url: ::std::option::Option<::std::string::String>,
    pub(crate) organizational_unit_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) operation_preferences: ::std::option::Option<crate::types::StackSetOperationPreferences>,
    pub(crate) operation_id: ::std::option::Option<::std::string::String>,
    pub(crate) call_as: ::std::option::Option<crate::types::CallAs>,
}
impl ImportStacksToStackSetInputBuilder {
    /// <p>The name of the stack set. The name must be unique in the Region where you create your stack set.</p>
    /// This field is required.
    pub fn stack_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stack set. The name must be unique in the Region where you create your stack set.</p>
    pub fn set_stack_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_set_name = input;
        self
    }
    /// <p>The name of the stack set. The name must be unique in the Region where you create your stack set.</p>
    pub fn get_stack_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_set_name
    }
    /// Appends an item to `stack_ids`.
    ///
    /// To override the contents of this collection use [`set_stack_ids`](Self::set_stack_ids).
    ///
    /// <p>The IDs of the stacks you are importing into a stack set. You import up to 10 stacks per stack set at a time.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub fn stack_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.stack_ids.unwrap_or_default();
        v.push(input.into());
        self.stack_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the stacks you are importing into a stack set. You import up to 10 stacks per stack set at a time.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub fn set_stack_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.stack_ids = input;
        self
    }
    /// <p>The IDs of the stacks you are importing into a stack set. You import up to 10 stacks per stack set at a time.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub fn get_stack_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.stack_ids
    }
    /// <p>The Amazon S3 URL which contains list of stack ids to be inputted.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub fn stack_ids_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_ids_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 URL which contains list of stack ids to be inputted.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub fn set_stack_ids_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_ids_url = input;
        self
    }
    /// <p>The Amazon S3 URL which contains list of stack ids to be inputted.</p>
    /// <p>Specify either <code>StackIds</code> or <code>StackIdsUrl</code>.</p>
    pub fn get_stack_ids_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_ids_url
    }
    /// Appends an item to `organizational_unit_ids`.
    ///
    /// To override the contents of this collection use [`set_organizational_unit_ids`](Self::set_organizational_unit_ids).
    ///
    /// <p>The list of OU ID's to which the stacks being imported has to be mapped as deployment target.</p>
    pub fn organizational_unit_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.organizational_unit_ids.unwrap_or_default();
        v.push(input.into());
        self.organizational_unit_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of OU ID's to which the stacks being imported has to be mapped as deployment target.</p>
    pub fn set_organizational_unit_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.organizational_unit_ids = input;
        self
    }
    /// <p>The list of OU ID's to which the stacks being imported has to be mapped as deployment target.</p>
    pub fn get_organizational_unit_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.organizational_unit_ids
    }
    /// <p>The user-specified preferences for how CloudFormation performs a stack set operation.</p>
    /// <p>For more information about maximum concurrent accounts and failure tolerance, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html#stackset-ops-options">Stack set operation options</a>.</p>
    pub fn operation_preferences(mut self, input: crate::types::StackSetOperationPreferences) -> Self {
        self.operation_preferences = ::std::option::Option::Some(input);
        self
    }
    /// <p>The user-specified preferences for how CloudFormation performs a stack set operation.</p>
    /// <p>For more information about maximum concurrent accounts and failure tolerance, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html#stackset-ops-options">Stack set operation options</a>.</p>
    pub fn set_operation_preferences(mut self, input: ::std::option::Option<crate::types::StackSetOperationPreferences>) -> Self {
        self.operation_preferences = input;
        self
    }
    /// <p>The user-specified preferences for how CloudFormation performs a stack set operation.</p>
    /// <p>For more information about maximum concurrent accounts and failure tolerance, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html#stackset-ops-options">Stack set operation options</a>.</p>
    pub fn get_operation_preferences(&self) -> &::std::option::Option<crate::types::StackSetOperationPreferences> {
        &self.operation_preferences
    }
    /// <p>A unique, user defined, identifier for the stack set operation.</p>
    pub fn operation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, user defined, identifier for the stack set operation.</p>
    pub fn set_operation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_id = input;
        self
    }
    /// <p>A unique, user defined, identifier for the stack set operation.</p>
    pub fn get_operation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_id
    }
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>For service managed stack sets, specify <code>DELEGATED_ADMIN</code>.</p></li>
    /// </ul>
    pub fn call_as(mut self, input: crate::types::CallAs) -> Self {
        self.call_as = ::std::option::Option::Some(input);
        self
    }
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>For service managed stack sets, specify <code>DELEGATED_ADMIN</code>.</p></li>
    /// </ul>
    pub fn set_call_as(mut self, input: ::std::option::Option<crate::types::CallAs>) -> Self {
        self.call_as = input;
        self
    }
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>For service managed stack sets, specify <code>DELEGATED_ADMIN</code>.</p></li>
    /// </ul>
    pub fn get_call_as(&self) -> &::std::option::Option<crate::types::CallAs> {
        &self.call_as
    }
    /// Consumes the builder and constructs a [`ImportStacksToStackSetInput`](crate::operation::import_stacks_to_stack_set::ImportStacksToStackSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::import_stacks_to_stack_set::ImportStacksToStackSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::import_stacks_to_stack_set::ImportStacksToStackSetInput {
            stack_set_name: self.stack_set_name,
            stack_ids: self.stack_ids,
            stack_ids_url: self.stack_ids_url,
            organizational_unit_ids: self.organizational_unit_ids,
            operation_preferences: self.operation_preferences,
            operation_id: self.operation_id,
            call_as: self.call_as,
        })
    }
}
