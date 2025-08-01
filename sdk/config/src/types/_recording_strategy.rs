// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the recording strategy of the configuration recorder.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecordingStrategy {
    /// <p>The recording strategy for the configuration recorder.</p>
    /// <ul>
    /// <li>
    /// <p>If you set this option to <code>ALL_SUPPORTED_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, excluding the global IAM resource types. You also must set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>. When Config adds support for a new resource type, Config automatically starts recording resources of that type. For a list of supported resource types, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html#supported-resources">Supported Resource Types</a> in the <i>Config developer guide</i>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>INCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for only the resource types that you specify in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>EXCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, except the resource types that you specify to exclude from being recorded in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p></li>
    /// </ul><note>
    /// <p><b>Required and optional fields</b></p>
    /// <p>The <code>recordingStrategy</code> field is optional when you set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>.</p>
    /// <p>The <code>recordingStrategy</code> field is optional when you list resource types in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p>
    /// <p>The <code>recordingStrategy</code> field is required if you list resource types to exclude from recording in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p>
    /// </note> <note>
    /// <p><b>Overriding fields</b></p>
    /// <p>If you choose <code>EXCLUSION_BY_RESOURCE_TYPES</code> for the recording strategy, the <code>exclusionByResourceTypes</code> field will override other properties in the request.</p>
    /// <p>For example, even if you set <code>includeGlobalResourceTypes</code> to false, global IAM resource types will still be automatically recorded in this option unless those resource types are specifically listed as exclusions in the <code>resourceTypes</code> field of <code>exclusionByResourceTypes</code>.</p>
    /// </note> <note>
    /// <p><b>Global resource types and the exclusion recording strategy</b></p>
    /// <p>By default, if you choose the <code>EXCLUSION_BY_RESOURCE_TYPES</code> recording strategy, when Config adds support for a new resource type in the Region where you set up the configuration recorder, including global resource types, Config starts recording resources of that type automatically.</p>
    /// <p>Unless specifically listed as exclusions, <code>AWS::RDS::GlobalCluster</code> will be recorded automatically in all supported Config Regions were the configuration recorder is enabled.</p>
    /// <p>IAM users, groups, roles, and customer managed policies will be recorded in the Region where you set up the configuration recorder if that is a Region where Config was available before February 2022. You cannot be record the global IAM resouce types in Regions supported by Config after February 2022. This list where you cannot record the global IAM resource types includes the following Regions:</p>
    /// <ul>
    /// <li>
    /// <p>Asia Pacific (Hyderabad)</p></li>
    /// <li>
    /// <p>Asia Pacific (Melbourne)</p></li>
    /// <li>
    /// <p>Canada West (Calgary)</p></li>
    /// <li>
    /// <p>Europe (Spain)</p></li>
    /// <li>
    /// <p>Europe (Zurich)</p></li>
    /// <li>
    /// <p>Israel (Tel Aviv)</p></li>
    /// <li>
    /// <p>Middle East (UAE)</p></li>
    /// </ul>
    /// </note>
    pub use_only: ::std::option::Option<crate::types::RecordingStrategyType>,
}
impl RecordingStrategy {
    /// <p>The recording strategy for the configuration recorder.</p>
    /// <ul>
    /// <li>
    /// <p>If you set this option to <code>ALL_SUPPORTED_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, excluding the global IAM resource types. You also must set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>. When Config adds support for a new resource type, Config automatically starts recording resources of that type. For a list of supported resource types, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html#supported-resources">Supported Resource Types</a> in the <i>Config developer guide</i>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>INCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for only the resource types that you specify in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>EXCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, except the resource types that you specify to exclude from being recorded in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p></li>
    /// </ul><note>
    /// <p><b>Required and optional fields</b></p>
    /// <p>The <code>recordingStrategy</code> field is optional when you set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>.</p>
    /// <p>The <code>recordingStrategy</code> field is optional when you list resource types in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p>
    /// <p>The <code>recordingStrategy</code> field is required if you list resource types to exclude from recording in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p>
    /// </note> <note>
    /// <p><b>Overriding fields</b></p>
    /// <p>If you choose <code>EXCLUSION_BY_RESOURCE_TYPES</code> for the recording strategy, the <code>exclusionByResourceTypes</code> field will override other properties in the request.</p>
    /// <p>For example, even if you set <code>includeGlobalResourceTypes</code> to false, global IAM resource types will still be automatically recorded in this option unless those resource types are specifically listed as exclusions in the <code>resourceTypes</code> field of <code>exclusionByResourceTypes</code>.</p>
    /// </note> <note>
    /// <p><b>Global resource types and the exclusion recording strategy</b></p>
    /// <p>By default, if you choose the <code>EXCLUSION_BY_RESOURCE_TYPES</code> recording strategy, when Config adds support for a new resource type in the Region where you set up the configuration recorder, including global resource types, Config starts recording resources of that type automatically.</p>
    /// <p>Unless specifically listed as exclusions, <code>AWS::RDS::GlobalCluster</code> will be recorded automatically in all supported Config Regions were the configuration recorder is enabled.</p>
    /// <p>IAM users, groups, roles, and customer managed policies will be recorded in the Region where you set up the configuration recorder if that is a Region where Config was available before February 2022. You cannot be record the global IAM resouce types in Regions supported by Config after February 2022. This list where you cannot record the global IAM resource types includes the following Regions:</p>
    /// <ul>
    /// <li>
    /// <p>Asia Pacific (Hyderabad)</p></li>
    /// <li>
    /// <p>Asia Pacific (Melbourne)</p></li>
    /// <li>
    /// <p>Canada West (Calgary)</p></li>
    /// <li>
    /// <p>Europe (Spain)</p></li>
    /// <li>
    /// <p>Europe (Zurich)</p></li>
    /// <li>
    /// <p>Israel (Tel Aviv)</p></li>
    /// <li>
    /// <p>Middle East (UAE)</p></li>
    /// </ul>
    /// </note>
    pub fn use_only(&self) -> ::std::option::Option<&crate::types::RecordingStrategyType> {
        self.use_only.as_ref()
    }
}
impl RecordingStrategy {
    /// Creates a new builder-style object to manufacture [`RecordingStrategy`](crate::types::RecordingStrategy).
    pub fn builder() -> crate::types::builders::RecordingStrategyBuilder {
        crate::types::builders::RecordingStrategyBuilder::default()
    }
}

/// A builder for [`RecordingStrategy`](crate::types::RecordingStrategy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecordingStrategyBuilder {
    pub(crate) use_only: ::std::option::Option<crate::types::RecordingStrategyType>,
}
impl RecordingStrategyBuilder {
    /// <p>The recording strategy for the configuration recorder.</p>
    /// <ul>
    /// <li>
    /// <p>If you set this option to <code>ALL_SUPPORTED_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, excluding the global IAM resource types. You also must set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>. When Config adds support for a new resource type, Config automatically starts recording resources of that type. For a list of supported resource types, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html#supported-resources">Supported Resource Types</a> in the <i>Config developer guide</i>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>INCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for only the resource types that you specify in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>EXCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, except the resource types that you specify to exclude from being recorded in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p></li>
    /// </ul><note>
    /// <p><b>Required and optional fields</b></p>
    /// <p>The <code>recordingStrategy</code> field is optional when you set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>.</p>
    /// <p>The <code>recordingStrategy</code> field is optional when you list resource types in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p>
    /// <p>The <code>recordingStrategy</code> field is required if you list resource types to exclude from recording in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p>
    /// </note> <note>
    /// <p><b>Overriding fields</b></p>
    /// <p>If you choose <code>EXCLUSION_BY_RESOURCE_TYPES</code> for the recording strategy, the <code>exclusionByResourceTypes</code> field will override other properties in the request.</p>
    /// <p>For example, even if you set <code>includeGlobalResourceTypes</code> to false, global IAM resource types will still be automatically recorded in this option unless those resource types are specifically listed as exclusions in the <code>resourceTypes</code> field of <code>exclusionByResourceTypes</code>.</p>
    /// </note> <note>
    /// <p><b>Global resource types and the exclusion recording strategy</b></p>
    /// <p>By default, if you choose the <code>EXCLUSION_BY_RESOURCE_TYPES</code> recording strategy, when Config adds support for a new resource type in the Region where you set up the configuration recorder, including global resource types, Config starts recording resources of that type automatically.</p>
    /// <p>Unless specifically listed as exclusions, <code>AWS::RDS::GlobalCluster</code> will be recorded automatically in all supported Config Regions were the configuration recorder is enabled.</p>
    /// <p>IAM users, groups, roles, and customer managed policies will be recorded in the Region where you set up the configuration recorder if that is a Region where Config was available before February 2022. You cannot be record the global IAM resouce types in Regions supported by Config after February 2022. This list where you cannot record the global IAM resource types includes the following Regions:</p>
    /// <ul>
    /// <li>
    /// <p>Asia Pacific (Hyderabad)</p></li>
    /// <li>
    /// <p>Asia Pacific (Melbourne)</p></li>
    /// <li>
    /// <p>Canada West (Calgary)</p></li>
    /// <li>
    /// <p>Europe (Spain)</p></li>
    /// <li>
    /// <p>Europe (Zurich)</p></li>
    /// <li>
    /// <p>Israel (Tel Aviv)</p></li>
    /// <li>
    /// <p>Middle East (UAE)</p></li>
    /// </ul>
    /// </note>
    pub fn use_only(mut self, input: crate::types::RecordingStrategyType) -> Self {
        self.use_only = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recording strategy for the configuration recorder.</p>
    /// <ul>
    /// <li>
    /// <p>If you set this option to <code>ALL_SUPPORTED_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, excluding the global IAM resource types. You also must set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>. When Config adds support for a new resource type, Config automatically starts recording resources of that type. For a list of supported resource types, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html#supported-resources">Supported Resource Types</a> in the <i>Config developer guide</i>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>INCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for only the resource types that you specify in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>EXCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, except the resource types that you specify to exclude from being recorded in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p></li>
    /// </ul><note>
    /// <p><b>Required and optional fields</b></p>
    /// <p>The <code>recordingStrategy</code> field is optional when you set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>.</p>
    /// <p>The <code>recordingStrategy</code> field is optional when you list resource types in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p>
    /// <p>The <code>recordingStrategy</code> field is required if you list resource types to exclude from recording in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p>
    /// </note> <note>
    /// <p><b>Overriding fields</b></p>
    /// <p>If you choose <code>EXCLUSION_BY_RESOURCE_TYPES</code> for the recording strategy, the <code>exclusionByResourceTypes</code> field will override other properties in the request.</p>
    /// <p>For example, even if you set <code>includeGlobalResourceTypes</code> to false, global IAM resource types will still be automatically recorded in this option unless those resource types are specifically listed as exclusions in the <code>resourceTypes</code> field of <code>exclusionByResourceTypes</code>.</p>
    /// </note> <note>
    /// <p><b>Global resource types and the exclusion recording strategy</b></p>
    /// <p>By default, if you choose the <code>EXCLUSION_BY_RESOURCE_TYPES</code> recording strategy, when Config adds support for a new resource type in the Region where you set up the configuration recorder, including global resource types, Config starts recording resources of that type automatically.</p>
    /// <p>Unless specifically listed as exclusions, <code>AWS::RDS::GlobalCluster</code> will be recorded automatically in all supported Config Regions were the configuration recorder is enabled.</p>
    /// <p>IAM users, groups, roles, and customer managed policies will be recorded in the Region where you set up the configuration recorder if that is a Region where Config was available before February 2022. You cannot be record the global IAM resouce types in Regions supported by Config after February 2022. This list where you cannot record the global IAM resource types includes the following Regions:</p>
    /// <ul>
    /// <li>
    /// <p>Asia Pacific (Hyderabad)</p></li>
    /// <li>
    /// <p>Asia Pacific (Melbourne)</p></li>
    /// <li>
    /// <p>Canada West (Calgary)</p></li>
    /// <li>
    /// <p>Europe (Spain)</p></li>
    /// <li>
    /// <p>Europe (Zurich)</p></li>
    /// <li>
    /// <p>Israel (Tel Aviv)</p></li>
    /// <li>
    /// <p>Middle East (UAE)</p></li>
    /// </ul>
    /// </note>
    pub fn set_use_only(mut self, input: ::std::option::Option<crate::types::RecordingStrategyType>) -> Self {
        self.use_only = input;
        self
    }
    /// <p>The recording strategy for the configuration recorder.</p>
    /// <ul>
    /// <li>
    /// <p>If you set this option to <code>ALL_SUPPORTED_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, excluding the global IAM resource types. You also must set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>. When Config adds support for a new resource type, Config automatically starts recording resources of that type. For a list of supported resource types, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html#supported-resources">Supported Resource Types</a> in the <i>Config developer guide</i>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>INCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for only the resource types that you specify in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p></li>
    /// <li>
    /// <p>If you set this option to <code>EXCLUSION_BY_RESOURCE_TYPES</code>, Config records configuration changes for all supported resource types, except the resource types that you specify to exclude from being recorded in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p></li>
    /// </ul><note>
    /// <p><b>Required and optional fields</b></p>
    /// <p>The <code>recordingStrategy</code> field is optional when you set the <code>allSupported</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a> to <code>true</code>.</p>
    /// <p>The <code>recordingStrategy</code> field is optional when you list resource types in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html">RecordingGroup</a>.</p>
    /// <p>The <code>recordingStrategy</code> field is required if you list resource types to exclude from recording in the <code>resourceTypes</code> field of <a href="https://docs.aws.amazon.com/config/latest/APIReference/API_ExclusionByResourceTypes.html">ExclusionByResourceTypes</a>.</p>
    /// </note> <note>
    /// <p><b>Overriding fields</b></p>
    /// <p>If you choose <code>EXCLUSION_BY_RESOURCE_TYPES</code> for the recording strategy, the <code>exclusionByResourceTypes</code> field will override other properties in the request.</p>
    /// <p>For example, even if you set <code>includeGlobalResourceTypes</code> to false, global IAM resource types will still be automatically recorded in this option unless those resource types are specifically listed as exclusions in the <code>resourceTypes</code> field of <code>exclusionByResourceTypes</code>.</p>
    /// </note> <note>
    /// <p><b>Global resource types and the exclusion recording strategy</b></p>
    /// <p>By default, if you choose the <code>EXCLUSION_BY_RESOURCE_TYPES</code> recording strategy, when Config adds support for a new resource type in the Region where you set up the configuration recorder, including global resource types, Config starts recording resources of that type automatically.</p>
    /// <p>Unless specifically listed as exclusions, <code>AWS::RDS::GlobalCluster</code> will be recorded automatically in all supported Config Regions were the configuration recorder is enabled.</p>
    /// <p>IAM users, groups, roles, and customer managed policies will be recorded in the Region where you set up the configuration recorder if that is a Region where Config was available before February 2022. You cannot be record the global IAM resouce types in Regions supported by Config after February 2022. This list where you cannot record the global IAM resource types includes the following Regions:</p>
    /// <ul>
    /// <li>
    /// <p>Asia Pacific (Hyderabad)</p></li>
    /// <li>
    /// <p>Asia Pacific (Melbourne)</p></li>
    /// <li>
    /// <p>Canada West (Calgary)</p></li>
    /// <li>
    /// <p>Europe (Spain)</p></li>
    /// <li>
    /// <p>Europe (Zurich)</p></li>
    /// <li>
    /// <p>Israel (Tel Aviv)</p></li>
    /// <li>
    /// <p>Middle East (UAE)</p></li>
    /// </ul>
    /// </note>
    pub fn get_use_only(&self) -> &::std::option::Option<crate::types::RecordingStrategyType> {
        &self.use_only
    }
    /// Consumes the builder and constructs a [`RecordingStrategy`](crate::types::RecordingStrategy).
    pub fn build(self) -> crate::types::RecordingStrategy {
        crate::types::RecordingStrategy { use_only: self.use_only }
    }
}
