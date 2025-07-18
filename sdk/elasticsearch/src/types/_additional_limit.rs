// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>List of limits that are specific to a given InstanceType and for each of it's <code> <code>InstanceRole</code> </code> .</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AdditionalLimit {
    /// <p>Name of Additional Limit is specific to a given InstanceType and for each of it's <code> <code>InstanceRole</code> </code> etc. <br><br>
    /// Attributes and their details: <br><br></p>
    /// <ul>
    /// <li>MaximumNumberOfDataNodesSupported</li> This attribute will be present in Master node only to specify how much data nodes upto which given <code> <code>ESPartitionInstanceType</code> </code> can support as master node.
    /// <li>MaximumNumberOfDataNodesWithoutMasterNode</li> This attribute will be present in Data node only to specify how much data nodes of given <code> <code>ESPartitionInstanceType</code> </code> upto which you don't need any master nodes to govern them.
    /// </ul>
    /// <p></p>
    pub limit_name: ::std::option::Option<::std::string::String>,
    /// <p>Value for given <code> <code>AdditionalLimit$LimitName</code> </code> .</p>
    pub limit_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AdditionalLimit {
    /// <p>Name of Additional Limit is specific to a given InstanceType and for each of it's <code> <code>InstanceRole</code> </code> etc. <br><br>
    /// Attributes and their details: <br><br></p>
    /// <ul>
    /// <li>MaximumNumberOfDataNodesSupported</li> This attribute will be present in Master node only to specify how much data nodes upto which given <code> <code>ESPartitionInstanceType</code> </code> can support as master node.
    /// <li>MaximumNumberOfDataNodesWithoutMasterNode</li> This attribute will be present in Data node only to specify how much data nodes of given <code> <code>ESPartitionInstanceType</code> </code> upto which you don't need any master nodes to govern them.
    /// </ul>
    /// <p></p>
    pub fn limit_name(&self) -> ::std::option::Option<&str> {
        self.limit_name.as_deref()
    }
    /// <p>Value for given <code> <code>AdditionalLimit$LimitName</code> </code> .</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.limit_values.is_none()`.
    pub fn limit_values(&self) -> &[::std::string::String] {
        self.limit_values.as_deref().unwrap_or_default()
    }
}
impl AdditionalLimit {
    /// Creates a new builder-style object to manufacture [`AdditionalLimit`](crate::types::AdditionalLimit).
    pub fn builder() -> crate::types::builders::AdditionalLimitBuilder {
        crate::types::builders::AdditionalLimitBuilder::default()
    }
}

/// A builder for [`AdditionalLimit`](crate::types::AdditionalLimit).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AdditionalLimitBuilder {
    pub(crate) limit_name: ::std::option::Option<::std::string::String>,
    pub(crate) limit_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl AdditionalLimitBuilder {
    /// <p>Name of Additional Limit is specific to a given InstanceType and for each of it's <code> <code>InstanceRole</code> </code> etc. <br><br>
    /// Attributes and their details: <br><br></p>
    /// <ul>
    /// <li>MaximumNumberOfDataNodesSupported</li> This attribute will be present in Master node only to specify how much data nodes upto which given <code> <code>ESPartitionInstanceType</code> </code> can support as master node.
    /// <li>MaximumNumberOfDataNodesWithoutMasterNode</li> This attribute will be present in Data node only to specify how much data nodes of given <code> <code>ESPartitionInstanceType</code> </code> upto which you don't need any master nodes to govern them.
    /// </ul>
    /// <p></p>
    pub fn limit_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.limit_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of Additional Limit is specific to a given InstanceType and for each of it's <code> <code>InstanceRole</code> </code> etc. <br><br>
    /// Attributes and their details: <br><br></p>
    /// <ul>
    /// <li>MaximumNumberOfDataNodesSupported</li> This attribute will be present in Master node only to specify how much data nodes upto which given <code> <code>ESPartitionInstanceType</code> </code> can support as master node.
    /// <li>MaximumNumberOfDataNodesWithoutMasterNode</li> This attribute will be present in Data node only to specify how much data nodes of given <code> <code>ESPartitionInstanceType</code> </code> upto which you don't need any master nodes to govern them.
    /// </ul>
    /// <p></p>
    pub fn set_limit_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.limit_name = input;
        self
    }
    /// <p>Name of Additional Limit is specific to a given InstanceType and for each of it's <code> <code>InstanceRole</code> </code> etc. <br><br>
    /// Attributes and their details: <br><br></p>
    /// <ul>
    /// <li>MaximumNumberOfDataNodesSupported</li> This attribute will be present in Master node only to specify how much data nodes upto which given <code> <code>ESPartitionInstanceType</code> </code> can support as master node.
    /// <li>MaximumNumberOfDataNodesWithoutMasterNode</li> This attribute will be present in Data node only to specify how much data nodes of given <code> <code>ESPartitionInstanceType</code> </code> upto which you don't need any master nodes to govern them.
    /// </ul>
    /// <p></p>
    pub fn get_limit_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.limit_name
    }
    /// Appends an item to `limit_values`.
    ///
    /// To override the contents of this collection use [`set_limit_values`](Self::set_limit_values).
    ///
    /// <p>Value for given <code> <code>AdditionalLimit$LimitName</code> </code> .</p>
    pub fn limit_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.limit_values.unwrap_or_default();
        v.push(input.into());
        self.limit_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Value for given <code> <code>AdditionalLimit$LimitName</code> </code> .</p>
    pub fn set_limit_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.limit_values = input;
        self
    }
    /// <p>Value for given <code> <code>AdditionalLimit$LimitName</code> </code> .</p>
    pub fn get_limit_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.limit_values
    }
    /// Consumes the builder and constructs a [`AdditionalLimit`](crate::types::AdditionalLimit).
    pub fn build(self) -> crate::types::AdditionalLimit {
        crate::types::AdditionalLimit {
            limit_name: self.limit_name,
            limit_values: self.limit_values,
        }
    }
}
