(defproject io.replikativ/geheimnis "0.1.1"
  :description "Cross-platform cryptography between cljs and clj."
  :url "https://github.com/replikativ/geheimnis"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [org.clojure/clojurescript "1.8.34"]
                 [org.clojure/data.codec "0.1.0"]
                 [io.replikativ/hasch "0.3.5-SNAPSHOT"]
                 [org.clojure/java.classpath "0.2.3"]]

  :plugins [[lein-cljsbuild "1.1.2"]
            [lein-doo "0.1.7"]]

  :profiles {:dev {:dependencies [[com.cemerick/piggieback "0.2.1"]]
                   :figwheel     {:nrepl-port       7888
                                  :nrepl-middleware ["cider.nrepl/cider-middleware"
                                                     "cemerick.piggieback/wrap-cljs-repl"]}
                   :plugins      [[lein-figwheel "0.5.0-2"]]}}

  :clean-targets ^{:protect false} ["target" "out" "resources/public/js"]

  :doo {:paths {:karma "./node_modules/karma/bin/karma"}}

  :cljsbuild
  {:builds [{:id           "cljs_repl"
             :source-paths ["src"]
             :figwheel     true
             :compiler
                           {:main          geheimnis.rsa
                            :asset-path    "js/out"
                            :output-to     "resources/public/js/client.js"
                            :output-dir    "resources/public/js/out"
                            :optimizations :none
                            :pretty-print  true}}
            {:id           "browser-test"
             :source-paths ["src" "test"]
             :compiler     {:output-to     "out/browser_tests.js"
                            :main          geheimnis.runner
                            :optimizations :none}}]})
