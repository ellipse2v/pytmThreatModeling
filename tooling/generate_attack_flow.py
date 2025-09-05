# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import uuid
import os
from datetime import datetime, timezone

# This script is designed to generate attack-flow (afb) files programmatically.
# It is based on the structure observed in existing .afb files and provides
# helper functions to create common objects like actions, assets, and the connections
# between them. This allows for the automated creation of attack flow diagrams
# that can be imported into the attack-flow application.

def create_anchor_objects(parent_instance_id):
    """
    Generates the boilerplate anchor objects required for each action or asset.
    These anchors are used by the application to draw connection lines.
    Returns a dictionary of anchor mappings and a list of the anchor objects.
    """
    anchors = {}
    anchor_objects = []
    for angle in range(0, 360, 30):
        anchor_id = str(uuid.uuid4())
        anchors[str(angle)] = anchor_id
        anchor_type = "vertical_anchor" if angle % 90 == 0 and angle % 180 != 0 else "horizontal_anchor"
        anchor_objects.append({
            "id": anchor_type,
            "instance": anchor_id,
            "latches": []
        })
    return anchors, anchor_objects

def create_action_object(name, technique_id, tactic_id, description=""):
    """
    Creates a full action object, including its properties and anchors.
    Returns the main action object and a list of all associated anchor objects.
    """
    instance_id = str(uuid.uuid4())
    anchors, anchor_objects = create_anchor_objects(instance_id)
    
    action_obj = {
        "id": "action",
        "instance": instance_id,
        "properties": [
            ["name", name],
            ["ttp", [
                ["tactic", tactic_id],
                ["technique", technique_id]
            ]],
            ["description", description],
            ["confidence", None],
            ["execution_start", None],
            ["execution_end", None]
        ],
        "anchors": anchors
    }
    return action_obj, anchor_objects

def create_asset_object(name, description=""):
    """
    Creates a full asset object, including its properties and anchors.
    Returns the main asset object and a list of all associated anchor objects.
    """
    instance_id = str(uuid.uuid4())
    anchors, anchor_objects = create_anchor_objects(instance_id)
    
    asset_obj = {
        "id": "asset",
        "instance": instance_id,
        "properties": [
            ["name", name],
            ["description", description]
        ],
        "anchors": anchors
    }
    return asset_obj, anchor_objects

def create_or_operator_object():
    """
    Creates an OR operator object, including its properties and anchors.
    """
    instance_id = str(uuid.uuid4())
    anchors, anchor_objects = create_anchor_objects(instance_id)
    
    operator_obj = {
        "id": "OR_operator",
        "instance": instance_id,
        "properties": [
            ["operator", "OR"]
        ],
        "anchors": anchors
    }
    return operator_obj, anchor_objects

def create_connection_objects(source_obj, target_obj, source_anchor_angle=270, target_anchor_angle=90):
    """
    Creates the set of objects needed to draw a line between two other objects.
    This is complex as it involves latches, handles, and the line itself.
    """
    # 1. Create the necessary UUIDs
    line_instance = str(uuid.uuid4())
    source_latch_instance = str(uuid.uuid4())
    target_latch_instance = str(uuid.uuid4())
    handle_instance = str(uuid.uuid4())

    # 2. Find the source and target anchor UUIDs from the objects themselves
    source_anchor_id = source_obj["anchors"][str(source_anchor_angle)]
    target_anchor_id = target_obj["anchors"][str(target_anchor_angle)]

    # 3. Create the objects
    dynamic_line = {
        "id": "dynamic_line",
        "instance": line_instance,
        "source": source_latch_instance,
        "target": target_latch_instance,
        "handles": [handle_instance]
    }
    source_latch = {"id": "generic_latch", "instance": source_latch_instance}
    target_latch = {"id": "generic_latch", "instance": target_latch_instance}
    handle = {"id": "generic_handle", "instance": handle_instance}

    # 4. Return all objects and the info needed to link them up
    return {
        "objects": [dynamic_line, source_latch, target_latch, handle],
        "source_anchor_id": source_anchor_id,
        "source_latch_instance": source_latch_instance,
        "target_anchor_id": target_anchor_id,
        "target_latch_instance": target_latch_instance,
    }

def generate_flow_file(name, description, objects, layout):
    """
    Assembles all the pieces into a final attack-flow dictionary.
    """
    flow_instance_id = str(uuid.uuid4())
    # Get the current time and format it as required by the .afb schema
    now = datetime.now().astimezone()

    # The main "drawable" objects are actions, assets, operators, and the lines connecting them.
    # The flow container should only reference the instance IDs of these.
    drawable_instances = [
        obj["instance"] for obj in objects
        if obj["id"] in ["action", "asset", "dynamic_line", "OR_operator"]
    ]

    # The main flow object that acts as a container
    flow_container = {
        "id": "flow",
        "instance": flow_instance_id,
        "properties": [
            ["name", name],
            ["description", description],
            ["author", [
                ["name", None],
                ["identity_class", None],
                ["contact_information", None]
            ]],
            ["scope", "incident"],
            ["external_references", []],
            ["created", {
                "time": now.isoformat(),
                "zone": str(now.tzinfo)
            }]
        ],
        # Use the filtered list of drawable object instances here
        "objects": drawable_instances
    }

    final_structure = {
        "schema": "attack_flow_v2",
        "theme": "dark_theme",
        # The top-level objects list contains everything
        "objects": [flow_container] + objects,
        "layout": layout,
        "camera": {"x": 0, "y": 0, "k": 1}
    }
    return final_structure

def main():
    """
    Main function to generate example .afb files.
    """
    output_dir = os.path.join(".", "output", "generated_flows")
    os.makedirs(output_dir, exist_ok=True)

    # --- Example 1: Simple Flow with a single action ---
    action, action_anchors = create_action_object(
        name="Phishing",
        technique_id="T1566",
        tactic_id="TA0001",
        description="An adversary sends a spearphishing email."
    )
    
    simple_flow_objects = [action] + action_anchors
    simple_layout = {
        action["instance"]: [100, 100]
    }

    simple_flow_structure = generate_flow_file(
        name="Simple Phishing Action",
        description="A flow with just one action.",
        objects=simple_flow_objects,
        layout=simple_layout
    )

    simple_flow_path = os.path.join(output_dir, "simple_action_flow.afb")
    with open(simple_flow_path, 'w') as f:
        json.dump(simple_flow_structure, f, indent=4)
    
    print(f"Generated simple flow: {simple_flow_path}")

    # --- Example 2: A flow with an asset at the top, connected to an action ---
    action2, action2_anchors = create_action_object(
        name="Valid Accounts",
        technique_id="T1078",
        tactic_id="TA0001",
        description="Adversary uses compromised credentials."
    )
    
    asset, asset_anchors = create_asset_object(
        name="Domain Controller",
        description="Critical authentication server."
    )

    # Create the connection from the asset (top) to the action (bottom)
    connection = create_connection_objects(asset, action2)

    # Attach the source latch to the asset's anchor
    for anchor in asset_anchors:
        if anchor["instance"] == connection["source_anchor_id"]:
            anchor["latches"].append(connection["source_latch_instance"])
            break
            
    # Attach the target latch to the action's anchor
    for anchor in action2_anchors:
        if anchor["instance"] == connection["target_anchor_id"]:
            anchor["latches"].append(connection["target_latch_instance"])
            break

    connected_flow_objects = [action2] + action2_anchors + [asset] + asset_anchors + connection["objects"]
    
    # Define the layout with the asset visually above the action, using negative coordinates for the top object
    connected_layout = {
        asset["instance"]: [100, -100],   # Y=-100 (top)
        action2["instance"]: [100, 100],    # Y=100 (bottom)
        # The layout needs positions for the latches to draw the line correctly
        connection["source_latch_instance"]: [100, -50],
        connection["target_latch_instance"]: [100, 50],
    }

    connected_flow_structure = generate_flow_file(
        name="Connected Action-Asset Flow",
        description="Shows an action targeting an asset.",
        objects=connected_flow_objects,
        layout=connected_layout
    )

    connected_flow_path = os.path.join(output_dir, "connected_action_flow.afb")
    with open(connected_flow_path, 'w') as f:
        json.dump(connected_flow_structure, f, indent=4)

    print(f"Generated connected flow: {connected_flow_path}")

    # --- Example 3: A flow with an OR condition ---
    or_asset, or_asset_anchors = create_asset_object("Target Server", "The ultimate target.")
    or_op, or_op_anchors = create_or_operator_object()
    or_action_A, or_action_A_anchors = create_action_object("Phishing", "T1566", "TA0001")
    or_action_B, or_action_B_anchors = create_action_object("External Remote Services", "T1133", "TA0001")

    # Connect actions to the OR operator
    conn_A_to_OR = create_connection_objects(or_action_A, or_op, source_anchor_angle=270, target_anchor_angle=150)
    conn_B_to_OR = create_connection_objects(or_action_B, or_op, source_anchor_angle=270, target_anchor_angle=210)
    
    # Connect OR operator to the asset
    conn_OR_to_asset = create_connection_objects(or_op, or_asset, source_anchor_angle=0, target_anchor_angle=270)

    # Attach latches for conn_A_to_OR
    for anchor in or_action_A_anchors:
        if anchor["instance"] == conn_A_to_OR["source_anchor_id"]:
            anchor["latches"].append(conn_A_to_OR["source_latch_instance"])
    for anchor in or_op_anchors:
        if anchor["instance"] == conn_A_to_OR["target_anchor_id"]:
            anchor["latches"].append(conn_A_to_OR["target_latch_instance"])

    # Attach latches for conn_B_to_OR
    for anchor in or_action_B_anchors:
        if anchor["instance"] == conn_B_to_OR["source_anchor_id"]:
            anchor["latches"].append(conn_B_to_OR["source_latch_instance"])
    for anchor in or_op_anchors:
        if anchor["instance"] == conn_B_to_OR["target_anchor_id"]:
            anchor["latches"].append(conn_B_to_OR["target_latch_instance"])

    # Attach latches for conn_OR_to_asset
    for anchor in or_op_anchors:
        if anchor["instance"] == conn_OR_to_asset["source_anchor_id"]:
            anchor["latches"].append(conn_OR_to_asset["source_latch_instance"])
    for anchor in or_asset_anchors:
        if anchor["instance"] == conn_OR_to_asset["target_anchor_id"]:
            anchor["latches"].append(conn_OR_to_asset["target_latch_instance"])

    or_flow_objects = (
        [or_asset] + or_asset_anchors +
        [or_op] + or_op_anchors +
        [or_action_A] + or_action_A_anchors +
        [or_action_B] + or_action_B_anchors +
        conn_A_to_OR["objects"] +
        conn_B_to_OR["objects"] +
        conn_OR_to_asset["objects"]
    )

    or_layout = {
        or_asset["instance"]: [0, -200],
        or_op["instance"]: [0, 0],
        or_action_A["instance"]: [-200, 200],
        or_action_B["instance"]: [200, 200],
        # Add latch positions for smooth lines
        conn_A_to_OR["source_latch_instance"]: [-200, 250],
        conn_A_to_OR["target_latch_instance"]: [-50, 50],
        conn_B_to_OR["source_latch_instance"]: [200, 250],
        conn_B_to_OR["target_latch_instance"]: [50, 50],
        conn_OR_to_asset["source_latch_instance"]: [0, -50],
        conn_OR_to_asset["target_latch_instance"]: [0, -150],
    }

    or_flow_structure = generate_flow_file(
        name="OR Condition Flow",
        description="Shows two actions leading to an OR operator.",
        objects=or_flow_objects,
        layout=or_layout
    )

    or_flow_path = os.path.join(output_dir, "or_condition_flow.afb")
    with open(or_flow_path, 'w') as f:
        json.dump(or_flow_structure, f, indent=4)

    print(f"Generated OR condition flow: {or_flow_path}")


if __name__ == "__main__":
    main()
