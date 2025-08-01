// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRdsDbInstancesInput {
    /// <p>The ID of the stack with which the instances are registered. The operation returns descriptions of all registered Amazon RDS instances.</p>
    pub stack_id: ::std::option::Option<::std::string::String>,
    /// <p>An array containing the ARNs of the instances to be described.</p>
    pub rds_db_instance_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeRdsDbInstancesInput {
    /// <p>The ID of the stack with which the instances are registered. The operation returns descriptions of all registered Amazon RDS instances.</p>
    pub fn stack_id(&self) -> ::std::option::Option<&str> {
        self.stack_id.as_deref()
    }
    /// <p>An array containing the ARNs of the instances to be described.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rds_db_instance_arns.is_none()`.
    pub fn rds_db_instance_arns(&self) -> &[::std::string::String] {
        self.rds_db_instance_arns.as_deref().unwrap_or_default()
    }
}
impl DescribeRdsDbInstancesInput {
    /// Creates a new builder-style object to manufacture [`DescribeRdsDbInstancesInput`](crate::operation::describe_rds_db_instances::DescribeRdsDbInstancesInput).
    pub fn builder() -> crate::operation::describe_rds_db_instances::builders::DescribeRdsDbInstancesInputBuilder {
        crate::operation::describe_rds_db_instances::builders::DescribeRdsDbInstancesInputBuilder::default()
    }
}

/// A builder for [`DescribeRdsDbInstancesInput`](crate::operation::describe_rds_db_instances::DescribeRdsDbInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRdsDbInstancesInputBuilder {
    pub(crate) stack_id: ::std::option::Option<::std::string::String>,
    pub(crate) rds_db_instance_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeRdsDbInstancesInputBuilder {
    /// <p>The ID of the stack with which the instances are registered. The operation returns descriptions of all registered Amazon RDS instances.</p>
    /// This field is required.
    pub fn stack_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the stack with which the instances are registered. The operation returns descriptions of all registered Amazon RDS instances.</p>
    pub fn set_stack_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_id = input;
        self
    }
    /// <p>The ID of the stack with which the instances are registered. The operation returns descriptions of all registered Amazon RDS instances.</p>
    pub fn get_stack_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_id
    }
    /// Appends an item to `rds_db_instance_arns`.
    ///
    /// To override the contents of this collection use [`set_rds_db_instance_arns`](Self::set_rds_db_instance_arns).
    ///
    /// <p>An array containing the ARNs of the instances to be described.</p>
    pub fn rds_db_instance_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.rds_db_instance_arns.unwrap_or_default();
        v.push(input.into());
        self.rds_db_instance_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array containing the ARNs of the instances to be described.</p>
    pub fn set_rds_db_instance_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.rds_db_instance_arns = input;
        self
    }
    /// <p>An array containing the ARNs of the instances to be described.</p>
    pub fn get_rds_db_instance_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.rds_db_instance_arns
    }
    /// Consumes the builder and constructs a [`DescribeRdsDbInstancesInput`](crate::operation::describe_rds_db_instances::DescribeRdsDbInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_rds_db_instances::DescribeRdsDbInstancesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_rds_db_instances::DescribeRdsDbInstancesInput {
            stack_id: self.stack_id,
            rds_db_instance_arns: self.rds_db_instance_arns,
        })
    }
}
