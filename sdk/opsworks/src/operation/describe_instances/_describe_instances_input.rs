// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInstancesInput {
    /// <p>A stack ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified stack.</p>
    pub stack_id: ::std::option::Option<::std::string::String>,
    /// <p>A layer ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified layer.</p>
    pub layer_id: ::std::option::Option<::std::string::String>,
    /// <p>An array of instance IDs to be described. If you use this parameter, <code>DescribeInstances</code> returns a description of the specified instances. Otherwise, it returns a description of every instance.</p>
    pub instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeInstancesInput {
    /// <p>A stack ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified stack.</p>
    pub fn stack_id(&self) -> ::std::option::Option<&str> {
        self.stack_id.as_deref()
    }
    /// <p>A layer ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified layer.</p>
    pub fn layer_id(&self) -> ::std::option::Option<&str> {
        self.layer_id.as_deref()
    }
    /// <p>An array of instance IDs to be described. If you use this parameter, <code>DescribeInstances</code> returns a description of the specified instances. Otherwise, it returns a description of every instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_ids.is_none()`.
    pub fn instance_ids(&self) -> &[::std::string::String] {
        self.instance_ids.as_deref().unwrap_or_default()
    }
}
impl DescribeInstancesInput {
    /// Creates a new builder-style object to manufacture [`DescribeInstancesInput`](crate::operation::describe_instances::DescribeInstancesInput).
    pub fn builder() -> crate::operation::describe_instances::builders::DescribeInstancesInputBuilder {
        crate::operation::describe_instances::builders::DescribeInstancesInputBuilder::default()
    }
}

/// A builder for [`DescribeInstancesInput`](crate::operation::describe_instances::DescribeInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInstancesInputBuilder {
    pub(crate) stack_id: ::std::option::Option<::std::string::String>,
    pub(crate) layer_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeInstancesInputBuilder {
    /// <p>A stack ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified stack.</p>
    pub fn stack_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A stack ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified stack.</p>
    pub fn set_stack_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_id = input;
        self
    }
    /// <p>A stack ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified stack.</p>
    pub fn get_stack_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_id
    }
    /// <p>A layer ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified layer.</p>
    pub fn layer_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.layer_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A layer ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified layer.</p>
    pub fn set_layer_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.layer_id = input;
        self
    }
    /// <p>A layer ID. If you use this parameter, <code>DescribeInstances</code> returns descriptions of the instances associated with the specified layer.</p>
    pub fn get_layer_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.layer_id
    }
    /// Appends an item to `instance_ids`.
    ///
    /// To override the contents of this collection use [`set_instance_ids`](Self::set_instance_ids).
    ///
    /// <p>An array of instance IDs to be described. If you use this parameter, <code>DescribeInstances</code> returns a description of the specified instances. Otherwise, it returns a description of every instance.</p>
    pub fn instance_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_ids.unwrap_or_default();
        v.push(input.into());
        self.instance_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of instance IDs to be described. If you use this parameter, <code>DescribeInstances</code> returns a description of the specified instances. Otherwise, it returns a description of every instance.</p>
    pub fn set_instance_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_ids = input;
        self
    }
    /// <p>An array of instance IDs to be described. If you use this parameter, <code>DescribeInstances</code> returns a description of the specified instances. Otherwise, it returns a description of every instance.</p>
    pub fn get_instance_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_ids
    }
    /// Consumes the builder and constructs a [`DescribeInstancesInput`](crate::operation::describe_instances::DescribeInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_instances::DescribeInstancesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_instances::DescribeInstancesInput {
            stack_id: self.stack_id,
            layer_id: self.layer_id,
            instance_ids: self.instance_ids,
        })
    }
}
