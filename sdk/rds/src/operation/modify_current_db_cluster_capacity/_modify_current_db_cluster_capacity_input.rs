// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyCurrentDbClusterCapacityInput {
    /// <p>The DB cluster identifier for the cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DB cluster.</p></li>
    /// </ul>
    pub db_cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The DB cluster capacity.</p>
    /// <p>When you change the capacity of a paused Aurora Serverless v1 DB cluster, it automatically resumes.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>For Aurora MySQL, valid capacity values are <code>1</code>, <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>128</code>, and <code>256</code>.</p></li>
    /// <li>
    /// <p>For Aurora PostgreSQL, valid capacity values are <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>192</code>, and <code>384</code>.</p></li>
    /// </ul>
    pub capacity: ::std::option::Option<i32>,
    /// <p>The amount of time, in seconds, that Aurora Serverless v1 tries to find a scaling point to perform seamless scaling before enforcing the timeout action. The default is 300.</p>
    /// <p>Specify a value between 10 and 600 seconds.</p>
    pub seconds_before_timeout: ::std::option::Option<i32>,
    /// <p>The action to take when the timeout is reached, either <code>ForceApplyCapacityChange</code> or <code>RollbackCapacityChange</code>.</p>
    /// <p><code>ForceApplyCapacityChange</code>, the default, sets the capacity to the specified value as soon as possible.</p>
    /// <p><code>RollbackCapacityChange</code> ignores the capacity change if a scaling point isn't found in the timeout period.</p>
    pub timeout_action: ::std::option::Option<::std::string::String>,
}
impl ModifyCurrentDbClusterCapacityInput {
    /// <p>The DB cluster identifier for the cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DB cluster.</p></li>
    /// </ul>
    pub fn db_cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.db_cluster_identifier.as_deref()
    }
    /// <p>The DB cluster capacity.</p>
    /// <p>When you change the capacity of a paused Aurora Serverless v1 DB cluster, it automatically resumes.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>For Aurora MySQL, valid capacity values are <code>1</code>, <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>128</code>, and <code>256</code>.</p></li>
    /// <li>
    /// <p>For Aurora PostgreSQL, valid capacity values are <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>192</code>, and <code>384</code>.</p></li>
    /// </ul>
    pub fn capacity(&self) -> ::std::option::Option<i32> {
        self.capacity
    }
    /// <p>The amount of time, in seconds, that Aurora Serverless v1 tries to find a scaling point to perform seamless scaling before enforcing the timeout action. The default is 300.</p>
    /// <p>Specify a value between 10 and 600 seconds.</p>
    pub fn seconds_before_timeout(&self) -> ::std::option::Option<i32> {
        self.seconds_before_timeout
    }
    /// <p>The action to take when the timeout is reached, either <code>ForceApplyCapacityChange</code> or <code>RollbackCapacityChange</code>.</p>
    /// <p><code>ForceApplyCapacityChange</code>, the default, sets the capacity to the specified value as soon as possible.</p>
    /// <p><code>RollbackCapacityChange</code> ignores the capacity change if a scaling point isn't found in the timeout period.</p>
    pub fn timeout_action(&self) -> ::std::option::Option<&str> {
        self.timeout_action.as_deref()
    }
}
impl ModifyCurrentDbClusterCapacityInput {
    /// Creates a new builder-style object to manufacture [`ModifyCurrentDbClusterCapacityInput`](crate::operation::modify_current_db_cluster_capacity::ModifyCurrentDbClusterCapacityInput).
    pub fn builder() -> crate::operation::modify_current_db_cluster_capacity::builders::ModifyCurrentDbClusterCapacityInputBuilder {
        crate::operation::modify_current_db_cluster_capacity::builders::ModifyCurrentDbClusterCapacityInputBuilder::default()
    }
}

/// A builder for [`ModifyCurrentDbClusterCapacityInput`](crate::operation::modify_current_db_cluster_capacity::ModifyCurrentDbClusterCapacityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyCurrentDbClusterCapacityInputBuilder {
    pub(crate) db_cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) capacity: ::std::option::Option<i32>,
    pub(crate) seconds_before_timeout: ::std::option::Option<i32>,
    pub(crate) timeout_action: ::std::option::Option<::std::string::String>,
}
impl ModifyCurrentDbClusterCapacityInputBuilder {
    /// <p>The DB cluster identifier for the cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DB cluster.</p></li>
    /// </ul>
    /// This field is required.
    pub fn db_cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DB cluster identifier for the cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DB cluster.</p></li>
    /// </ul>
    pub fn set_db_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_cluster_identifier = input;
        self
    }
    /// <p>The DB cluster identifier for the cluster being modified. This parameter isn't case-sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must match the identifier of an existing DB cluster.</p></li>
    /// </ul>
    pub fn get_db_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_cluster_identifier
    }
    /// <p>The DB cluster capacity.</p>
    /// <p>When you change the capacity of a paused Aurora Serverless v1 DB cluster, it automatically resumes.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>For Aurora MySQL, valid capacity values are <code>1</code>, <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>128</code>, and <code>256</code>.</p></li>
    /// <li>
    /// <p>For Aurora PostgreSQL, valid capacity values are <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>192</code>, and <code>384</code>.</p></li>
    /// </ul>
    pub fn capacity(mut self, input: i32) -> Self {
        self.capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The DB cluster capacity.</p>
    /// <p>When you change the capacity of a paused Aurora Serverless v1 DB cluster, it automatically resumes.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>For Aurora MySQL, valid capacity values are <code>1</code>, <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>128</code>, and <code>256</code>.</p></li>
    /// <li>
    /// <p>For Aurora PostgreSQL, valid capacity values are <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>192</code>, and <code>384</code>.</p></li>
    /// </ul>
    pub fn set_capacity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.capacity = input;
        self
    }
    /// <p>The DB cluster capacity.</p>
    /// <p>When you change the capacity of a paused Aurora Serverless v1 DB cluster, it automatically resumes.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>For Aurora MySQL, valid capacity values are <code>1</code>, <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>128</code>, and <code>256</code>.</p></li>
    /// <li>
    /// <p>For Aurora PostgreSQL, valid capacity values are <code>2</code>, <code>4</code>, <code>8</code>, <code>16</code>, <code>32</code>, <code>64</code>, <code>192</code>, and <code>384</code>.</p></li>
    /// </ul>
    pub fn get_capacity(&self) -> &::std::option::Option<i32> {
        &self.capacity
    }
    /// <p>The amount of time, in seconds, that Aurora Serverless v1 tries to find a scaling point to perform seamless scaling before enforcing the timeout action. The default is 300.</p>
    /// <p>Specify a value between 10 and 600 seconds.</p>
    pub fn seconds_before_timeout(mut self, input: i32) -> Self {
        self.seconds_before_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time, in seconds, that Aurora Serverless v1 tries to find a scaling point to perform seamless scaling before enforcing the timeout action. The default is 300.</p>
    /// <p>Specify a value between 10 and 600 seconds.</p>
    pub fn set_seconds_before_timeout(mut self, input: ::std::option::Option<i32>) -> Self {
        self.seconds_before_timeout = input;
        self
    }
    /// <p>The amount of time, in seconds, that Aurora Serverless v1 tries to find a scaling point to perform seamless scaling before enforcing the timeout action. The default is 300.</p>
    /// <p>Specify a value between 10 and 600 seconds.</p>
    pub fn get_seconds_before_timeout(&self) -> &::std::option::Option<i32> {
        &self.seconds_before_timeout
    }
    /// <p>The action to take when the timeout is reached, either <code>ForceApplyCapacityChange</code> or <code>RollbackCapacityChange</code>.</p>
    /// <p><code>ForceApplyCapacityChange</code>, the default, sets the capacity to the specified value as soon as possible.</p>
    /// <p><code>RollbackCapacityChange</code> ignores the capacity change if a scaling point isn't found in the timeout period.</p>
    pub fn timeout_action(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timeout_action = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The action to take when the timeout is reached, either <code>ForceApplyCapacityChange</code> or <code>RollbackCapacityChange</code>.</p>
    /// <p><code>ForceApplyCapacityChange</code>, the default, sets the capacity to the specified value as soon as possible.</p>
    /// <p><code>RollbackCapacityChange</code> ignores the capacity change if a scaling point isn't found in the timeout period.</p>
    pub fn set_timeout_action(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timeout_action = input;
        self
    }
    /// <p>The action to take when the timeout is reached, either <code>ForceApplyCapacityChange</code> or <code>RollbackCapacityChange</code>.</p>
    /// <p><code>ForceApplyCapacityChange</code>, the default, sets the capacity to the specified value as soon as possible.</p>
    /// <p><code>RollbackCapacityChange</code> ignores the capacity change if a scaling point isn't found in the timeout period.</p>
    pub fn get_timeout_action(&self) -> &::std::option::Option<::std::string::String> {
        &self.timeout_action
    }
    /// Consumes the builder and constructs a [`ModifyCurrentDbClusterCapacityInput`](crate::operation::modify_current_db_cluster_capacity::ModifyCurrentDbClusterCapacityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_current_db_cluster_capacity::ModifyCurrentDbClusterCapacityInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::modify_current_db_cluster_capacity::ModifyCurrentDbClusterCapacityInput {
                db_cluster_identifier: self.db_cluster_identifier,
                capacity: self.capacity,
                seconds_before_timeout: self.seconds_before_timeout,
                timeout_action: self.timeout_action,
            },
        )
    }
}
