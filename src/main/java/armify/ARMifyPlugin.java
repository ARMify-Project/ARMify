/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package armify;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
		status = PluginStatus.RELEASED,
		packageName = ExamplesPluginPackage.NAME,
		category = PluginCategoryNames.EXAMPLES,
		shortDescription = "Hello World",
		description = "Sample plugin to demonstrate how to write a plugin with a dockable GUI component."
)
//@formatter:on

public class ARMifyPlugin extends ProgramPlugin {

    private ARMifyComponentProvider provider = null;

    public ARMifyPlugin(PluginTool tool) {
        super(tool);

        provider = new ARMifyComponentProvider(tool, getName());
        tool.addComponentProvider(provider, false);
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        if (provider != null) {
            provider.locationChanged(currentProgram, location);
        }
    }

    @Override
    public void dispose() {
        if (provider != null) {
            provider.setVisible(false);
        }
    }
}
