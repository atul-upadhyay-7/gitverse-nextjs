import { DependencyGraphService } from "./dependency-graph";

export interface DependencyImpact {
  affectedFiles: string[];
  dependencyPaths: Record<string, string[]>;
  downstreamCount: number;
}

export class DependencyGraphAnalyzer {
  public static async analyzeImpact(repoUrl: string, changedFiles: string[]): Promise<DependencyImpact> {
    const dependencyPaths: Record<string, string[]> = {};
    const affectedSet = new Set<string>();

    try {
      const graph = await DependencyGraphService.buildGraph(repoUrl);
      
      for (const file of changedFiles) {
        const dependents = DependencyGraphService.getDownstreamDependents(graph, file, 3);
        if (dependents.length > 0) {
          dependencyPaths[file] = dependents;
          dependents.forEach(dep => affectedSet.add(dep));
        }
      }
    } catch (e) {
      console.warn("Failed to build or traverse dependency graph for impact analysis", e);
    }

    return {
      affectedFiles: Array.from(affectedSet),
      dependencyPaths,
      downstreamCount: affectedSet.size
    };
  }
}
