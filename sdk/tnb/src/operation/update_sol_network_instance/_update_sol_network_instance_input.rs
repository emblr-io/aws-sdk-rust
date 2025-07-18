// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateSolNetworkInstanceInput {
    /// <p>ID of the network instance.</p>
    pub ns_instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of update.</p>
    /// <ul>
    /// <li>
    /// <p>Use the <code>MODIFY_VNF_INFORMATION</code> update type, to update a specific network function configuration, in the network instance.</p></li>
    /// <li>
    /// <p>Use the <code>UPDATE_NS</code> update type, to update the network instance to a new network service descriptor.</p></li>
    /// </ul>
    pub update_type: ::std::option::Option<crate::types::UpdateSolNetworkType>,
    /// <p>Identifies the network function information parameters and/or the configurable properties of the network function to be modified.</p>
    /// <p>Include this property only if the update type is <code>MODIFY_VNF_INFORMATION</code>.</p>
    pub modify_vnf_info_data: ::std::option::Option<crate::types::UpdateSolNetworkModify>,
    /// <p>Identifies the network service descriptor and the configurable properties of the descriptor, to be used for the update.</p>
    /// <p>Include this property only if the update type is <code>UPDATE_NS</code>.</p>
    pub update_ns: ::std::option::Option<crate::types::UpdateSolNetworkServiceData>,
    /// <p>A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key and an optional value. When you use this API, the tags are only applied to the network operation that is created. These tags are not applied to the network instance. Use tags to search and filter your resources or track your Amazon Web Services costs.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateSolNetworkInstanceInput {
    /// <p>ID of the network instance.</p>
    pub fn ns_instance_id(&self) -> ::std::option::Option<&str> {
        self.ns_instance_id.as_deref()
    }
    /// <p>The type of update.</p>
    /// <ul>
    /// <li>
    /// <p>Use the <code>MODIFY_VNF_INFORMATION</code> update type, to update a specific network function configuration, in the network instance.</p></li>
    /// <li>
    /// <p>Use the <code>UPDATE_NS</code> update type, to update the network instance to a new network service descriptor.</p></li>
    /// </ul>
    pub fn update_type(&self) -> ::std::option::Option<&crate::types::UpdateSolNetworkType> {
        self.update_type.as_ref()
    }
    /// <p>Identifies the network function information parameters and/or the configurable properties of the network function to be modified.</p>
    /// <p>Include this property only if the update type is <code>MODIFY_VNF_INFORMATION</code>.</p>
    pub fn modify_vnf_info_data(&self) -> ::std::option::Option<&crate::types::UpdateSolNetworkModify> {
        self.modify_vnf_info_data.as_ref()
    }
    /// <p>Identifies the network service descriptor and the configurable properties of the descriptor, to be used for the update.</p>
    /// <p>Include this property only if the update type is <code>UPDATE_NS</code>.</p>
    pub fn update_ns(&self) -> ::std::option::Option<&crate::types::UpdateSolNetworkServiceData> {
        self.update_ns.as_ref()
    }
    /// <p>A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key and an optional value. When you use this API, the tags are only applied to the network operation that is created. These tags are not applied to the network instance. Use tags to search and filter your resources or track your Amazon Web Services costs.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateSolNetworkInstanceInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateSolNetworkInstanceInput");
        formatter.field("ns_instance_id", &self.ns_instance_id);
        formatter.field("update_type", &self.update_type);
        formatter.field("modify_vnf_info_data", &self.modify_vnf_info_data);
        formatter.field("update_ns", &self.update_ns);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl UpdateSolNetworkInstanceInput {
    /// Creates a new builder-style object to manufacture [`UpdateSolNetworkInstanceInput`](crate::operation::update_sol_network_instance::UpdateSolNetworkInstanceInput).
    pub fn builder() -> crate::operation::update_sol_network_instance::builders::UpdateSolNetworkInstanceInputBuilder {
        crate::operation::update_sol_network_instance::builders::UpdateSolNetworkInstanceInputBuilder::default()
    }
}

/// A builder for [`UpdateSolNetworkInstanceInput`](crate::operation::update_sol_network_instance::UpdateSolNetworkInstanceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateSolNetworkInstanceInputBuilder {
    pub(crate) ns_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) update_type: ::std::option::Option<crate::types::UpdateSolNetworkType>,
    pub(crate) modify_vnf_info_data: ::std::option::Option<crate::types::UpdateSolNetworkModify>,
    pub(crate) update_ns: ::std::option::Option<crate::types::UpdateSolNetworkServiceData>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateSolNetworkInstanceInputBuilder {
    /// <p>ID of the network instance.</p>
    /// This field is required.
    pub fn ns_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ns_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID of the network instance.</p>
    pub fn set_ns_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ns_instance_id = input;
        self
    }
    /// <p>ID of the network instance.</p>
    pub fn get_ns_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ns_instance_id
    }
    /// <p>The type of update.</p>
    /// <ul>
    /// <li>
    /// <p>Use the <code>MODIFY_VNF_INFORMATION</code> update type, to update a specific network function configuration, in the network instance.</p></li>
    /// <li>
    /// <p>Use the <code>UPDATE_NS</code> update type, to update the network instance to a new network service descriptor.</p></li>
    /// </ul>
    /// This field is required.
    pub fn update_type(mut self, input: crate::types::UpdateSolNetworkType) -> Self {
        self.update_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of update.</p>
    /// <ul>
    /// <li>
    /// <p>Use the <code>MODIFY_VNF_INFORMATION</code> update type, to update a specific network function configuration, in the network instance.</p></li>
    /// <li>
    /// <p>Use the <code>UPDATE_NS</code> update type, to update the network instance to a new network service descriptor.</p></li>
    /// </ul>
    pub fn set_update_type(mut self, input: ::std::option::Option<crate::types::UpdateSolNetworkType>) -> Self {
        self.update_type = input;
        self
    }
    /// <p>The type of update.</p>
    /// <ul>
    /// <li>
    /// <p>Use the <code>MODIFY_VNF_INFORMATION</code> update type, to update a specific network function configuration, in the network instance.</p></li>
    /// <li>
    /// <p>Use the <code>UPDATE_NS</code> update type, to update the network instance to a new network service descriptor.</p></li>
    /// </ul>
    pub fn get_update_type(&self) -> &::std::option::Option<crate::types::UpdateSolNetworkType> {
        &self.update_type
    }
    /// <p>Identifies the network function information parameters and/or the configurable properties of the network function to be modified.</p>
    /// <p>Include this property only if the update type is <code>MODIFY_VNF_INFORMATION</code>.</p>
    pub fn modify_vnf_info_data(mut self, input: crate::types::UpdateSolNetworkModify) -> Self {
        self.modify_vnf_info_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Identifies the network function information parameters and/or the configurable properties of the network function to be modified.</p>
    /// <p>Include this property only if the update type is <code>MODIFY_VNF_INFORMATION</code>.</p>
    pub fn set_modify_vnf_info_data(mut self, input: ::std::option::Option<crate::types::UpdateSolNetworkModify>) -> Self {
        self.modify_vnf_info_data = input;
        self
    }
    /// <p>Identifies the network function information parameters and/or the configurable properties of the network function to be modified.</p>
    /// <p>Include this property only if the update type is <code>MODIFY_VNF_INFORMATION</code>.</p>
    pub fn get_modify_vnf_info_data(&self) -> &::std::option::Option<crate::types::UpdateSolNetworkModify> {
        &self.modify_vnf_info_data
    }
    /// <p>Identifies the network service descriptor and the configurable properties of the descriptor, to be used for the update.</p>
    /// <p>Include this property only if the update type is <code>UPDATE_NS</code>.</p>
    pub fn update_ns(mut self, input: crate::types::UpdateSolNetworkServiceData) -> Self {
        self.update_ns = ::std::option::Option::Some(input);
        self
    }
    /// <p>Identifies the network service descriptor and the configurable properties of the descriptor, to be used for the update.</p>
    /// <p>Include this property only if the update type is <code>UPDATE_NS</code>.</p>
    pub fn set_update_ns(mut self, input: ::std::option::Option<crate::types::UpdateSolNetworkServiceData>) -> Self {
        self.update_ns = input;
        self
    }
    /// <p>Identifies the network service descriptor and the configurable properties of the descriptor, to be used for the update.</p>
    /// <p>Include this property only if the update type is <code>UPDATE_NS</code>.</p>
    pub fn get_update_ns(&self) -> &::std::option::Option<crate::types::UpdateSolNetworkServiceData> {
        &self.update_ns
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key and an optional value. When you use this API, the tags are only applied to the network operation that is created. These tags are not applied to the network instance. Use tags to search and filter your resources or track your Amazon Web Services costs.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key and an optional value. When you use this API, the tags are only applied to the network operation that is created. These tags are not applied to the network instance. Use tags to search and filter your resources or track your Amazon Web Services costs.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key and an optional value. When you use this API, the tags are only applied to the network operation that is created. These tags are not applied to the network instance. Use tags to search and filter your resources or track your Amazon Web Services costs.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`UpdateSolNetworkInstanceInput`](crate::operation::update_sol_network_instance::UpdateSolNetworkInstanceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_sol_network_instance::UpdateSolNetworkInstanceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_sol_network_instance::UpdateSolNetworkInstanceInput {
            ns_instance_id: self.ns_instance_id,
            update_type: self.update_type,
            modify_vnf_info_data: self.modify_vnf_info_data,
            update_ns: self.update_ns,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for UpdateSolNetworkInstanceInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateSolNetworkInstanceInputBuilder");
        formatter.field("ns_instance_id", &self.ns_instance_id);
        formatter.field("update_type", &self.update_type);
        formatter.field("modify_vnf_info_data", &self.modify_vnf_info_data);
        formatter.field("update_ns", &self.update_ns);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
